#include "Client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <polarssl/bignum.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <sys/socket.h>
#include <sys/types.h>

//NOTE 1024 is norm =)
#define DH_P_SIZE 512
#define GENERATOR "4"
#define BUFFER_SIZE 1000
#define TIMER_COUNTER 10


using namespace std;

Client::Client()
{
  dh_info = new dhm_context;
  client_socket = socket( AF_INET, SOCK_STREAM, 0 );
  if( client_socket == -1 )
    cout << "ERROR: Failed to create socket\n";
 
  //char* buffer;
  //buffer = BN_bn2dec( diffihellman_info->p );
  //cout << "p = " << buffer << "\n";
  //OPENSSL_free( buffer );
  
}

Client::~Client()
{
}

void Client::connect_to_server( const char* server_address, const char* server_port )
{
  struct addrinfo* address_p = get_addrinfo( server_address, server_port );
  if( connect( client_socket, address_p->ai_addr, address_p->ai_addrlen ) != 0 ) 
  {
    cout << "ERROR: can not connect!\n";
    exit( -1 );
  }
  secure_connection();
}

dh_base* Client::generate_dh_base()
{
  dh_base* result = new dh_base;
  mpi Q;
  entropy_context entropy_info;
  ctr_drbg_context generator_info;
  
  mpi_init(&result->G);
  mpi_init(&result->P);
  mpi_init(&Q);
  mpi_read_string(&result->G, 10, GENERATOR);
  entropy_init(&entropy_info);
  
  //TODO make not NULL
  ctr_drbg_init(&generator_info, entropy_func, &entropy_info, NULL, 0);
  mpi_gen_prime(&result->P, DH_P_SIZE, 3, ctr_drbg_random, &generator_info);
  
  mpi_sub_int(&Q, &result->P, 1);
  mpi_div_int(&Q, NULL, &Q, 2);
  if(mpi_is_prime(&Q, ctr_drbg_random, &generator_info) != 0)
  {
    cout << "ERROR: prime generated ";
    return NULL;
  }
  return result;
}

void Client::secure_connection()
{
  unsigned char buf[BUFFER_SIZE];
  entropy_context entropy_info;
  ctr_drbg_context generator_info;
  size_t len;

  entropy_init(&entropy_info);
  //TODO make not NULL
  ctr_drbg_init(&generator_info, entropy_func, &entropy_info, NULL, 0);

  dh_base* dh_base = generate_dh_base();
  dh_info->P = dh_base->P;
  dh_info->G = dh_base->G;
  dhm_make_params(dh_info, 256, buf, &len, ctr_drbg_random, &generator_info);
  send_raw_message(buf, static_cast<u_int16_t>(len), DH_TAKE_BASE);
  unsigned char* server_key_data = get_message(); 

}

void Client::disconnect()
{

}

//TODO make secure! This ver - just for debug!
void Client::send_message( string message )
{
  char* buffer = const_cast<char*>(message.c_str());
  send_raw_message(reinterpret_cast<void*>(buffer), static_cast<u_int16_t>(message.length()));
}

void Client::send_raw_message( void* data, u_int16_t data_length, message_type type )
{
  u_int16_t message_length;
  message_length = sizeof(message_type) + data_length;
  char* buffer = new char[message_length + sizeof(u_int16_t)];
  memcpy(buffer, &message_length, sizeof(u_int16_t));
  memcpy(&(buffer[sizeof(u_int16_t)]), reinterpret_cast<void*>(&type), sizeof(message_type));
  memcpy(&(buffer[sizeof(u_int16_t)+sizeof(message_type)]), data, data_length);

  if(write(client_socket, buffer, message_length + sizeof(u_int16_t)) < 0)
  {
    cout << "ERROR: can not send message!";
  }
}

unsigned char* Client::get_message()
{
  unsigned char buffer[BUFFER_SIZE];
  bool message_received = false;
  bool message_size_known = false;
  fd_set socket_to_read;
  Socket max_socket_to_check = client_socket + 1;
  struct timeval time_to_wait;
  u_int16_t message_size;
  bool timeout = false;
  int counter = TIMER_COUNTER;
  unsigned char* result = NULL;

  /* Let select() wait for 1.05 sec */
  time_to_wait.tv_sec = 1.0;
  time_to_wait.tv_usec = 50;

  FD_SET(client_socket, &socket_to_read);

  while(!message_received && !timeout)
  {
    fd_set sockets_ready_to_read;
    sockets_ready_to_read = socket_to_read;
    select(max_socket_to_check, &sockets_ready_to_read, NULL,  NULL, &time_to_wait);
  
    if(FD_ISSET(client_socket, &sockets_ready_to_read) != 0)
    {
      /* Real size of messgae that we can read now*/
      int current_message_size = recv(client_socket, buffer, BUFFER_SIZE, MSG_PEEK);

      /* If we dont have enough data to get next message size - try to get it */
      if(!message_size_known)
      {   
        /* Learn, if there is enough new data to get size. If not enough - skeep. */
        if( current_message_size >= MESSAGE_SIZE_LENGTH )
        { 
          message_size_known = true;
          recv(client_socket, buffer, MESSAGE_SIZE_LENGTH, 0);
          message_size = *((u_int16_t*)buffer);
          current_message_size -= MESSAGE_SIZE_LENGTH;
        }  
        else continue; 
      };  

      /* Check, do we got enough data? If not - skeep. */
      if(current_message_size >= message_size)
      {
        cout << "DEBUG: client get answer! Length: " << message_size << endl;
        recv(client_socket, buffer, message_size, 0 );
        result = (unsigned char*)malloc(message_size);
        memcpy(result, buffer, message_size);
        message_received = true;
      }

    }
    if( counter-- == 0 )
    {
      cout << "TIMEOUT!\n";
      timeout = true;
    }
  }
  return result;
}

struct addrinfo* Client::get_addrinfo( const char* addr, const char* port )
{
  struct addrinfo hints = {0};
  struct addrinfo* result;

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST || AI_NUMERICSERV;
  hints.ai_protocol = IPPROTO_TCP;

  if(  getaddrinfo( addr, port, &hints, &result ) != 0 )
  {
    cout << "ERROR: " << " Worng addr or port!\n";
    exit( -1 );
  }

  return result;
}

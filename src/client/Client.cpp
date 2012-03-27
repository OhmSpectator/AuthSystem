#include "Client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <polarssl/aes.h>
#include <polarssl/bignum.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <polarssl/havege.h>
#include <sys/socket.h>
#include <sys/types.h>

#define DH_P_SIZE 128 
#define GENERATOR "4"
#define BUFFER_SIZE 1000
#define TIMER_COUNTER 10


using namespace std;

Client::Client()
{
  dh_info = new dhm_context;
  aes_info = new aes_context;
  entropy_context entropy_info;
  entropy_init(&entropy_info);
  ctr_drbg_init(&generator_info, entropy_func, &entropy_info, (unsigned char*)"STRING", 6);
  ctr_drbg_set_prediction_resistance(&generator_info, CTR_DRBG_PR_OFF);
  client_socket = socket( AF_INET, SOCK_STREAM, 0 );
  if( client_socket == -1 )
    cout << "ERROR: Failed to create socket\n";
}

Client::~Client()
{
  free(aes_key.data);
}

void Client::connect_to_server( const char* server_address, const char* server_port )
{
  struct addrinfo* address_p = get_addrinfo( server_address, server_port );
  if( connect( client_socket, address_p->ai_addr, address_p->ai_addrlen ) != 0 ) 
  {
    cout << "ERROR: can not connect!\n";
    exit(-1);
  }
  if( !secure_connection() )
  {
    cout << "ERROR: cannot secure connection!";
    exit(-1);
  }
}

/*Returns type of the message
 */
message_type Client::get_message_type(unsigned char* message)
{
  message_type result;
  memcpy((void*)(&result), message, sizeof(message_type));
  return result;
}


/*Return a pointer to a payload of the message
 */
unsigned char* Client::get_data(unsigned char* message)
{
  return message + sizeof(message_type);
}

dh_base* Client::generate_dh_base()
{
  dh_base* result = new dh_base;
  mpi Q;

  mpi_init(&result->G);
  mpi_init(&result->P);
  mpi_init(&Q);
  mpi_read_string(&result->G, 10, GENERATOR);

  mpi_gen_prime(&result->P, DH_P_SIZE, 1, ctr_drbg_random, &generator_info);

  mpi_sub_int(&Q, &result->P, 1);
  mpi_div_int(&Q, NULL, &Q, 2);
  if(mpi_is_prime(&Q, ctr_drbg_random, &generator_info) != 0)
  {
    cout << "ERROR: prime generated ";
    return NULL;
  }
  return result;
}

bool Client::secure_connection()
{
  unsigned char buf[BUFFER_SIZE];
  size_t len;

  dh_base* dh_base = generate_dh_base();
  dh_info->P = dh_base->P;
  dh_info->G = dh_base->G;
  dhm_make_params(dh_info, 256, buf, &len, ctr_drbg_random, &generator_info);
  send_raw_message(buf, static_cast<u_int16_t>(len), DH_TAKE_BASE);
  unsigned char* server_answer = get_message(&len);
  if( get_message_type(server_answer) != DH_TAKE_PUB_KEY )
  {
    cout << "ERROR: Answer corrupted\n";
    return false;
  }
  dhm_read_public(dh_info, get_data(server_answer), dh_info->len);
  free(server_answer);
  dhm_calc_secret(dh_info, buf, &len);
  aes_key.data = (unsigned char*)malloc(len);
  memcpy(aes_key.data,buf,len);
  aes_key.len = len;
  return true;
}

void Client::disconnect()
{

}

unsigned char* Client::encrypt_message(unsigned char* message, u_int16_t data_size, u_int16_t* new_length)
{
  unsigned char* result = NULL;
  unsigned char IV[16];
  
  ctr_drbg_random(&generator_info, IV, 16);
  aes_setkey_enc(aes_info, aes_key.data, aes_key.len<<3);

  u_int16_t extra_length = 0;
  u_int16_t pred_new_msg_length = data_size + (u_int16_t)sizeof(u_int16_t) + sizeof(IV);
  u_int16_t bad_data_length = (u_int16_t)((pred_new_msg_length) & (u_int16_t)15);
  if( bad_data_length != 0 )
    extra_length = (u_int16_t)16 - bad_data_length;

  result = (unsigned char*)malloc(sizeof(IV) + sizeof(u_int16_t) + data_size + extra_length);
  memcpy(result, (unsigned char*)(IV),sizeof(IV));
  memcpy(result + sizeof(IV), (unsigned char*)(&extra_length), sizeof(u_int16_t));
  memcpy(result + sizeof(IV) + sizeof(u_int16_t), message, data_size);
  if(extra_length != 0)
    memset(result + sizeof(IV) + sizeof(u_int16_t) + data_size, 0, extra_length );
  //TODO strange behaviour. IV looks like no playing a role.
  for( int i = 0; i < 16; i++ )
    result[i] ^= IV[i];
  aes_crypt_cbc(aes_info, AES_ENCRYPT, sizeof(IV) + sizeof(u_int16_t) + data_size + extra_length, IV, result, result );
  *new_length = sizeof(IV) + sizeof(u_int16_t) + data_size + extra_length;

  return result;
}


unsigned char* Client::decrypt_message(unsigned char* message, u_int16_t data_size, u_int16_t* new_length)
{
  unsigned char* result = NULL;
  unsigned char* buffer = NULL;
  unsigned char IV[16];

  buffer = (unsigned char*)malloc(data_size - sizeof(IV));
  memcpy(IV, message, sizeof(IV));

  aes_setkey_dec(aes_info, aes_key.data, aes_key.len<<3);
  aes_crypt_cbc(aes_info, AES_DECRYPT, data_size - sizeof(IV), IV, message + sizeof(IV), buffer);

  u_int16_t extra_length = 0;
  memcpy((unsigned char*)(&extra_length), buffer, sizeof(u_int16_t));

  *new_length = data_size - sizeof(IV) - sizeof(u_int16_t) - extra_length;

  result = (unsigned char*)malloc(*new_length);
  memcpy(result, buffer + sizeof(u_int16_t), *new_length);

  free(buffer);
  return result;
}


void Client::send_raw_message(unsigned char* data, u_int16_t data_length, message_type type)
{
  u_int16_t message_length;
  message_length = sizeof(message_type) + data_length;
  unsigned char* buffer = new unsigned char[message_length + sizeof(u_int16_t)];
  memcpy(buffer, &message_length, sizeof(u_int16_t));
  memcpy(&(buffer[sizeof(u_int16_t)]), reinterpret_cast<unsigned char*>(&type), sizeof(message_type));
  memcpy(&(buffer[sizeof(u_int16_t)+sizeof(message_type)]), data, data_length);
  if(write(client_socket, buffer, message_length + sizeof(u_int16_t)) < 0)
  {
    cout << "ERROR: can not send message!";
  }
}

void Client::send_message(unsigned char* message, u_int16_t length, message_type type)
{
  u_int16_t new_length;
  unsigned char buffer[length + sizeof(message_type)];
  unsigned char* encrypted_message; 
  memcpy(buffer, (unsigned char*)(&type), sizeof(message_type));
  memcpy(buffer + sizeof(message_type), message, length);
  encrypted_message = encrypt_message(buffer, length + sizeof(message_type),  &new_length);
  send_raw_message(encrypted_message, new_length, SECURED);
  free(encrypted_message);
}



unsigned char* Client::get_message(size_t* len)
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
  *len = 0;

  /* Let select() wait for 1.05 sec */
  time_to_wait.tv_sec = 1.0;
  time_to_wait.tv_usec = 5;

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
        recv(client_socket, buffer, message_size, 0 );
        result = (unsigned char*)malloc(message_size);
        memcpy(result, buffer, message_size);
        message_received = true;
        *len = message_size;

        /*cout << "RCV: " << endl;
          for(int i = 0; i < message_size; i++)
          cout << result[i];
          cout << endl;*/

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

  if(getaddrinfo( addr, port, &hints, &result ) != 0)
  {
    cout << "ERROR: " << " Worng addr or port!\n";
    exit( -1 );
  }

  return result;
}

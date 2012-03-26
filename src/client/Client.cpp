#include "Client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <sys/socket.h>
#include <sys/types.h>

#define PRIME_NUM_LENGTH 43
#define GENERATOR_NUM 5

using namespace std;

Client::Client()
{
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

void Client::secure_connection()
{
  /*bool dh_params_good = false;
  while( !dh_params_good )
  {
    diffihellman_info = DH_generate_parameters(PRIME_NUM_LENGTH, GENERATOR_NUM, NULL, NULL);
    int error_code;
    dh_params_good = (DH_check(diffihellman_info, &error_code)!=0);
  }
  send_raw_message(diffihellman_info, static_cast<u_int16_t>(sizeof(*diffihellman_info)), DH_TAKE_BASE);
  
  DH* dh_info;
  dh_info = (DH*)malloc(sizeof(DH));
  memcpy((void*)(dh_info),(void*)diffihellman_info,sizeof(DH));
  int error_code;
  DH_check(dh_info, &error_code);
  
  for(int i=0; i<(int)sizeof(DH); i++)
  { 
    printf("%d", (int)(((char*)(dh_info))[i]));
    if(i != (int)sizeof(DH)-1)
    { 
      printf(":");
    }
  }
  printf("\n");
  
  if(DH_generate_key(diffihellman_info) != 1)
  {
    printf("DEBUG: ok\n");
  }
  */
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

string Client::retrieve_message()
{
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

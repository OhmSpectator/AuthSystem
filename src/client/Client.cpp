#include "Client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>


using namespace std;

Client::Client()
{
  client_socket = socket( AF_INET, SOCK_STREAM, 0 );
  if( client_socket == -1 )
    cout << "ERROR: Failed to create socket\n";
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
}

void Client::disconnect()
{
}

//TODO make secure! This ver - just for debug!
void Client::send_message( string message )
{
  string norm_message = make_message( message );
  if( write( client_socket, norm_message.c_str(), norm_message.length() ) < 0 )
  {
    cout << "ERROR: can not send message!";
  }
}

void Client::send_raw_message( string message )
{
  string norm_message = make_message( message );
  if( write( client_socket, norm_message.c_str(), norm_message.length() ) < 0 )
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

string Client::make_message( string message )
{

  u_int16_t length;
  string result;
  char* buffer = new char[ message.length() + 2 ];

  length = static_cast<u_int16_t>( message.length() );

  memcpy( buffer, &length, 2);
  memcpy( &(buffer[2]), message.c_str(), message.length() );

  result = string( buffer, message.length() + 2 );

  return result;
}

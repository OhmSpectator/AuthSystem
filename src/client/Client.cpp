#include <cstdio>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "Client.h"

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

void Client::send_message( string message )
{
  const char* norm_message = make_message( message );
  if( write( client_socket, norm_message, strlen(norm_message) ) < 0 )
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

const char* Client::make_message( string message )
{

  u_int16_t length;
  string result;

  length = static_cast<u_int16_t>( message.length() );

  cout << "not normalized length = " << length << endl;

  char* buffer_for_num;
  memcpy( buffer_for_num, reinterpret_cast<char*>(&length), 2);
  buffer_for_num[2] =  '\0';
  printf( "a = %s\n", buffer_for_num ); 
  
  u_int16_t new_length = *reinterpret_cast<u_int16_t*>( buffer_for_num );
  cout << "come back = " << new_length << endl;
  printf("a = %s\n", buffer_for_num);
  //cout << "buf = " << buffer_for_num;
  //cout << "buf len = " << string(buffer_for_num).length() << endl;

  result =  string( buffer_for_num ) + message;

  cout << "normalized length = " << result.length() << endl;

  /*strcpy( result, static_cast<const char*>( buffer ) );
  cout << "RRRRRRRRRRRR\n";
  strcpy( &(result[2]), message.c_str() );
  cout << "TTTTTTTTTTTT\n";*/
  
  cout << "result = " << result << endl;

  return result.c_str();
}

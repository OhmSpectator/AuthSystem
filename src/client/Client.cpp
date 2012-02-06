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
  //TODO test if AF_INET is ok (server working via PF_INET)
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

  char* buffer;
  buffer = reinterpret_cast<char*>( &length );
  buffer[2] = '\0';
  u_int16_t num_buf = *reinterpret_cast<u_int16_t*>( buffer );
  cout << "come back = " << num_buf << endl;

  cout << "buf len = " << string(buffer).length() << endl;

  result = string( buffer ) + message;

  cout << "normalized length = " << result.length() << endl;

  /*strcpy( result, static_cast<const char*>( buffer ) );
  cout << "RRRRRRRRRRRR\n";
  strcpy( &(result[2]), message.c_str() );
  cout << "TTTTTTTTTTTT\n";*/
  
  cout << "result = " << result << endl;

  return result.c_str();
}

#ifndef CLIENT_H
#define CLIENT_H

#include "NetTypes.h"

#include <openssl/dh.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>

using namespace std;

class Client
{
  public:
  
  Client();
  ~Client();
  
  void connect_to_server( const char* server_adress, const char* server_port );
  void disconnect();
  void send_message( string message );

  private:

  Socket client_socket;
  DH* diffihellman_info; 

  bool connection_secured;
  struct addrinfo* get_addrinfo( const char* addr, const char* port );
  string retrieve_message();
  void send_raw_message( void* data, u_int16_t length );
  void secure_connection();
};

#endif

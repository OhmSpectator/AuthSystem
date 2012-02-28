#ifndef CLIENT_H
#define CLIENT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <string>

#include "NetTypes.h"

using namespace std;

class Client
{
  public:
  
  Client();
  ~Client();
  
  void connect_to_server( const char* server_adress, const char* server_port );
  void disconnect();
  void send_message( string message );
  void secure_connection();

  private:

  //Clent config info
  Socket client_socket;
  //PortNum client_port;

  //Server config info
  //Address server_address;
  //PortNum server_port;

  struct addrinfo* get_addrinfo( const char* addr, const char* port );
  string make_message( string message );
  string retrieve_message();
  void send_raw_message( string message );
};

#endif

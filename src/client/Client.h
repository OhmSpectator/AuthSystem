#ifndef CLIENT_H
#define CLIENT_H

#include "../NetTypes.h"

#include <polarssl/bignum.h>
#include <polarssl/dhm.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct dh_b
{
  mpi G;
  mpi P;
} dh_base;

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
  dhm_context* dh_info;
  Data aes_key;

  bool connection_secured;
  struct addrinfo* get_addrinfo( const char* addr, const char* port );
  unsigned char* get_message(size_t*);
  void send_raw_message( void* data, u_int16_t length, message_type=UNKNOWN_TYPE );
  void secure_connection();
  dh_base* generate_dh_base();
};

#endif

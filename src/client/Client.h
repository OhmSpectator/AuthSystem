#ifndef CLIENT_H
#define CLIENT_H

#include "../NetTypes.h"

#include <polarssl/aes.h>
#include <polarssl/bignum.h>
#include <polarssl/dhm.h>
#include <polarssl/ctr_drbg.h>
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
  void send_message(unsigned char* message, u_int16_t length, message_type type=UNKNOWN_TYPE);
  
  //TODO make private
  login_password* login_data;
  unsigned char* get_message(size_t*);
  message_type get_message_type(unsigned char* msg);
  unsigned char* decrypt_message(unsigned char* msg, u_int16_t size, u_int16_t* new_size);
  unsigned char* get_data(unsigned char* msg);
  bool can_retry;
  bool loggedin;

  private:

  Socket client_socket;
  dhm_context* dh_info;
  aes_context* aes_info;
  ctr_drbg_context generator_info;
  Data aes_key;

  unsigned char* encrypt_message(unsigned char* msg, u_int16_t size, u_int16_t* new_size);
  struct addrinfo* get_addrinfo( const char* addr, const char* port );
  void send_raw_message( unsigned char* data, u_int16_t length, message_type=UNKNOWN_TYPE );
  bool secure_connection();
  dh_base* generate_dh_base();
};

#endif

#ifndef NETTYPES_H
#define NETTYPES_H

#include <netinet/in.h>

#define MESSAGE_SIZE_LENGTH 2
#define TIMEOUT_COUNTER 10

#define PASSWORD_MAX_SIZE 20
#define LOGIN_MAX_SIZE 20

typedef struct in_addr Address;
typedef u_int16_t PortNum;
typedef int Socket;

typedef struct data
{
  unsigned char* data;
  size_t len;
} Data;

typedef struct lp
{
  unsigned char login[LOGIN_MAX_SIZE];
  unsigned char password[PASSWORD_MAX_SIZE];
} login_password;

typedef enum m_type           
{
  DH_TAKE_BASE,
  DH_TAKE_PUB_KEY,
  SECURED,
  WANT_LOGIN,
  WELCOME,
  RETRY,
  STOP,
  DIE,
  UNKNOWN_TYPE
} message_type;  

#endif

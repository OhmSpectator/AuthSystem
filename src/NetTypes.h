#ifndef NETTYPES_H
#define NETTYPES_H

#include <netinet/in.h>

#define MESSAGE_SIZE_LENGTH 2
#define TIMEOUT_COUNTER 10

typedef struct in_addr Address;
typedef u_int16_t PortNum;
typedef int Socket;

typedef struct data
{
  unsigned char* data;
  size_t len;
} Data;

typedef enum m_type           
{
  DH_TAKE_BASE,
  DH_TAKE_PUB_KEY,
  SECURED,
  UNKNOWN_TYPE
} message_type;  

#endif

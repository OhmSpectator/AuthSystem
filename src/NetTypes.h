#ifndef NETTYPES_H
#define NETTYPES_H

#include <netinet/in.h>

typedef struct in_addr Address;
typedef u_int16_t PortNum;
typedef int Socket;

typedef enum m_type           
{
  DH_TAKE_PRIME,
  DH_GIVE_ME_INIT,
  DH_TAKE_INIT,
  DH_TAKE_MY_BASE,
  UNKNOWN_TYPE
} message_type;  

#endif

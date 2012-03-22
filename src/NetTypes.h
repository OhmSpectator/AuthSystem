#ifndef NETTYPES_H
#define NETTYPES_H

#include <netinet/in.h>

typedef struct in_addr Address;
typedef u_int16_t PortNum;
typedef int Socket;

typedef enum m_type           
{
  DH_TAKE_BASE,
  UNKNOWN_TYPE
} message_type;  

#endif

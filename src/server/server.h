/* Structure to describe server state in interacton with a particular client*/

#include <polarssl/dhm.h>
#include "../NetTypes.h"

#define KNOWN 1
#define UNKNOWN 0

#define BUFFER_SIZE 1024

typedef enum s_id
{
  CONNECTION_ACCEPTED,
  INIT_SEND,
  AES_KEY_CREATED	
} state_id;

typedef struct c_state
{
  /* Client socket  */
  int socket;

  /* Is length of next message known? 
     Known only if we've got all 2 bytes of length
   */
  u_int8_t message_size_known;

  /* Length of the next message */
  u_int16_t message_size;

  /* Curret state identificator */
  state_id current_state;

  /* Wait for messge of the following type */
  message_type next_message_type;

  /* Message buffer */
  char message_buffer[BUFFER_SIZE];

  /* Diffie-Hellman info for AES key creation*/
  dhm_context* dh_info;

} connection_state;



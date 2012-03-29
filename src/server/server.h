/* Structure to describe server state in interacton with a particular client*/

#include <polarssl/aes.h>
#include <polarssl/dhm.h>
#include "../NetTypes.h"

#define KNOWN 1
#define UNKNOWN 0

#define ACCEPTED 1
#define DENIED 0

#define MAX_ATTEMPTS_TO_LOGIN 3

#define LOGIN_SIZE 20
#define PASSWORD_SIZE 20


#define BUFFER_SIZE 1024

typedef enum s_id
{
  CONNECTION_ACCEPTED,
  CONNECTION_REFUSED,
  CONNECTION_SECURED,
  CONNECTION_LOGGEDIN,
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

  /*AES key*/
  Data aes_key;

  /*AES context*/
  aes_context* aes_info;

  /*Number of attempts to login*/
  int login_attempts;

  struct in_addr address;

} connection_state;



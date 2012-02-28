#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include "server.h"

#define OK 0
#define ERROR -1

/* Number of bytes to describe message length */
#define MESSAGE_SIZE_LENGTH 2

/* Max number of connections */
#define MAX_CONNECTIONS_NUM 1024

/* Creates new socket. 
   Returns the socket descriptor. In case of an error returns ERROR (-1)
*/
int create_socket(  )
{
  int result;

  result = ERROR;

  /* get system info about TCP protocol */
  struct protoent* protocol_info = getprotobyname( "TCP" );
  int protocol_sys_number = protocol_info->p_proto;

  /* Socket creation. 
     PF_INET - make working via IPv4 
     SOCK_STREAM - make working via TCP/IP
   */
  result = socket( PF_INET, SOCK_STREAM, protocol_sys_number );

  if( result == -1 )
    printf( "ERROR: failed to create socket!\n" );

  return result;
}


/* Binds socket descriptor to a given port on all net interfaces in a system.
   Returns OK (0). In case of an error return ERROR (-1)
 */
int bind_socket( int socket, u_int16_t port )
{
  int result; 
  struct sockaddr_in socket_address;

  result = ERROR;

  /* Create structure to define socket address */
  socket_address.sin_family = AF_INET; /* magic constant */ 
  socket_address.sin_addr.s_addr = INADDR_ANY; /* binds to all localhost addresses */
  socket_address.sin_port = port;

  /* bind socket descriptor to a given port on all net interfaces in a system */
  if( bind( socket, ( struct sockaddr* )( &socket_address ), sizeof( socket_address ) ) == -1  )
    printf( "ERROR: failed to bind socket on port %i! %s!\n", ntohs( port ), strerror( errno ) );
  else
    result = OK;

  return result;
}

/* Creates a new socket, binds it to a given port on all net interfaces on a system, allows to listen it.
   Returns the socket descriptor. In case of an error returns ERROR (-1)
 */
int make_socket( u_int16_t port )
{
  int result;
  int new_socket;

  result = ERROR;

  /* Create! */
  new_socket = create_socket();

  /* Bind! */
  if( bind_socket( new_socket, port ) == ERROR )
    return result;

  /* Listen! */
  if( listen( new_socket, 5 ) == -1 )
    return result;

  result = new_socket;

  return result;
}

/* Get a port number from user defined options.
   Return value will be in a net byte order.
   Port must be defined in -p option (GNU style).
   Return port number. In case of an error returns 0.
 */
u_int16_t get_port_from_params( int argc, char* argv[] )
{
  u_int16_t result;
  int current_opt;

  result = 0;
  current_opt = 0;
  opterr = 0;

  while( ( current_opt = getopt( argc, argv, "p:" ) ) != -1 )
  {
    switch( current_opt )
    {
      case 'p':
        result = ( u_int16_t )atoi( optarg );
        break;
    }
  }

  if( result == 0 )
    printf( "ERROR: Port must be defined in -p option!\n" );
  else
    /* make net byte order */
    result = htons( result );

  return result;
}

/*TODO test*/
/* Compacts array, deleting unused element */
void compact_array( void*(*array_p)[], int max_index, int deleting_index )
{
  if( deleting_index != max_index )
  {
    int i;
    for( i = deleting_index; i < max_index; i++ )
      ( *array_p )[ i ] = ( *array_p )[ i + 1 ];
  }
}


/* Returns index of the socket in connections state array. If there is no such socket, returns ERROR(-1) */
int get_id_by_socket( int socket, connection_state*(*connections_array_p)[], int connections_number )
{
  int i;
  int result = ERROR;

  for( i = 0; i < connections_number; i++ )
  {
    if( (*connections_array_p)[i]->socket == socket )
    {
      result = i;
      break;
    }
  }
  return result;
}

/* Process of server work.
   Returns OK(0), if no errers occured during work. Otherwise returns ERROR(-1)
 */
int run_server( int server_socket )
{
  int result;
  int i;

  /* Temprory storage for a new client socket. Th number be stored in struct of all client sockets */
  int new_client_socket;

  /* New client info. Will be lost after client descriptor will be stored in common storage. */
  struct sockaddr_in new_client_info;
  socklen_t client_info_size;

  /* All socket descriptor, that we will use for I/O operations */
  fd_set sockets_to_read, sockets_to_write;
  struct timeval time_to_wait;
  int max_socket_descriptor = server_socket;

  /* Info about our connections */
  /* Array of connections states.  */
  connection_state* connections[MAX_CONNECTIONS_NUM];
  /* Current connectons number */
  u_int16_t connections_number = 0;

  /* Let select() wait for 0.05 sec */
  time_to_wait.tv_sec = 0.0;
  time_to_wait.tv_usec = 50;

  client_info_size = sizeof( new_client_info );

  /* By default we want to read from server socket, waiting for incoming conection */
  FD_SET( server_socket, &sockets_to_read );

  /* Main loop.
     Waiting for connections and handling.
   */
  while( 1 )
  {
    int current_descriptor;
    /* Socket descriptors, ONLY that are READY for I/O */
    fd_set sockets_ready_to_read, sockets_ready_to_write;

    /* ASSUME, that all interesting descriptors are ready for I/O operation */
    sockets_ready_to_read = sockets_to_read;
    sockets_ready_to_write = sockets_to_write;

    /* Get sets of descriptors that are REALY ready for I/O operations */
    if( select( max_socket_descriptor + 1, &sockets_ready_to_read, &sockets_ready_to_write, NULL, &time_to_wait ) == -1 )
    {
      printf( "ERROR: Cannot test sockets for I/O operations!\n" );
      result =  ERROR;
      break;
    }

    /* Testing all system descriptors. */
    for( current_descriptor = 1; current_descriptor <=  max_socket_descriptor && result != ERROR; current_descriptor++ )
    {
      /* If it's a discriptor from a set of ready to be read from, handle it. */ 
      if( FD_ISSET( current_descriptor, &sockets_ready_to_read ) != 0 )
      {
        /* If it's a server descriptor, a new connetion comes. Handle id.  */
        if( current_descriptor == server_socket )
        {
          new_client_socket = accept( server_socket, ( struct sockaddr* )( &new_client_info ), &client_info_size );
          if( new_client_socket == -1 )
          {
            printf( "ERROR: cannot accept a new connection!\n" );
            result = ERROR;
            break;
          }
          /* Get info about new connection and remember it. */
          else
          {
            printf( "New client connected! It's: %s\n", inet_ntoa( new_client_info.sin_addr ) );
            connections[connections_number] = ( connection_state* )malloc( sizeof( connection_state ) );
            connections[connections_number]->socket = new_client_socket;
            connections[connections_number]->message_size_known = UNKNOWN;
            connections[connections_number]->current_state = CONNECTION_ACCEPTED;
            connections[connections_number]->next_message_type = DH_GIVE_ME_INIT;
            connections_number++;
            FD_SET( new_client_socket, &sockets_to_read );
            if( new_client_socket > max_socket_descriptor )
              max_socket_descriptor = new_client_socket;
          }
        }
        /* Otherwise - a new information came for one of opened connections. Handle it. */
        else
        {
          char buffer[ BUFFER_SIZE ];
          int socket_id;
          /* The connection state */
          connection_state* current_state_p;

          /* Real size of messgae that we can read now*/
          int current_message_size = recv( current_descriptor, buffer, BUFFER_SIZE, MSG_PEEK );

          /*printf( "DEBUG: new information from old connection!\n" );*/

          /* Find info about this connection */
          if( ( socket_id = get_id_by_socket( current_descriptor, &connections, connections_number ) ) == ERROR )
          {
            printf( "ERROR: Cannot find connection state!\n"  );
            result = ERROR;
            break;
          }

          current_state_p = connections[socket_id];

          /* If we dont have enough data to get next message size - try to get it */
          if( current_state_p->message_size_known == UNKNOWN )
          {
            /* Learn, if there is enough new data to get size. If not enough - skeep. */
            if( current_message_size >= MESSAGE_SIZE_LENGTH )
            {
              current_state_p->message_size_known = KNOWN;
              recv( current_descriptor, buffer, MESSAGE_SIZE_LENGTH, 0 );
              buffer[ MESSAGE_SIZE_LENGTH ] = '\0';
              current_state_p->message_size = *(( u_int16_t* )buffer);
              current_message_size -= MESSAGE_SIZE_LENGTH;

            }
          };
          /* Check - do we know message size now?  If we know - try to get it. Skeep otherwise.*/
          if( current_state_p->message_size_known == KNOWN )
          {
            /* Check, do we got enough data? If not - skeep. */
            if( current_message_size >= current_state_p->message_size )
            {
              recv( current_descriptor, buffer, current_state_p->message_size, 0 );
              buffer[current_state_p->message_size] = '\0';
              printf( "DEBUG: Got new message!\n%s\n", buffer );
              current_state_p->message_size_known= UNKNOWN;
            }

            else
            {
              recv( current_descriptor, buffer, current_message_size, 0 );
              buffer[current_message_size] = '\0';
              printf( "DEBUG: Got new message!\n============\n%s\n============\n", buffer );
              current_state_p->message_size_known= UNKNOWN;
            }
          }

        }
      }

    }

  }

  for( i = 0; i < connections_number; i++ )
    if( connections[i] != NULL )
      free( connections[i] );

  return result;
}

int main( int argc, char* argv[] )
{
  u_int16_t port;
  int socket;

  port = get_port_from_params( argc, argv );
  if( port == 0 )
  {
    printf( "ERROR: failed to get port from options!\nTerminated!\n" );
    exit( ERROR );
  }

  socket = make_socket( port );
  if( socket == ERROR  )
  {
    printf( "ERROR: failed to make working socket!\nTerminated!\n" );
    exit( ERROR );
  }

  if( run_server( socket ) == ERROR )
  {
    printf( "ERROR: error occured during server work!\nTerminated!\n" );
    exit( ERROR );
  }

  close( socket );
  printf( "The server has worked in a normal mode, no run-time errors were found.\nTerminated!\n" );

  return OK;
}
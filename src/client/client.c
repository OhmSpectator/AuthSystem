#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

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

int main ( int argc, char** argv )
{
  u_int16_t client_port, server_port;
  int client_socket;

  server_port = get_port_from_params( argc, argv );


      u_int16_t length;
      char* message;
      int file; 

      length = ( u_int16_t )strlen( argv[1] );
      message = ( char* )( &length );
      file = open( "message", O_WRONLY | O_CREAT );
      write( file, message, 2 );
      write( file, argv[1], length );
      close( file );

    return 0;
}

#include <iostream>

#include "Console.h"
#include "Client.h"
#include "../NetTypes.h"

using namespace std;

int main()
{
  Console console;
  Client client;
  const char* server_address = console.get_server_addr();
  const char* server_port = console.get_server_port();
  client.connect_to_server( server_address, server_port );
  while( client.can_retry && !client.loggedin )
  {
    client.login_data = console.ask_for_logpass();
    client.send_message((unsigned char*)(client.login_data), sizeof(login_password), WANT_LOGIN);
    size_t answer_len;
    unsigned char* answer = client.get_message(&answer_len);
    if( answer != NULL )
    {
      if( client.get_message_type(answer) != SECURED )
        cout << "Answer corrupted!\n";
      u_int16_t new_answer_len;
      unsigned char* decrypted_answer = client.decrypt_message(client.get_data(answer),answer_len-sizeof(message_type), &new_answer_len);
      switch( client.get_message_type(decrypted_answer) )
      {
        case WELCOME:
          {
            cout << "You are in!\n";
            client.loggedin = true;
            break;
          }
        case RETRY:
          {
            cout << "Retry...\n";
            break;
          }
        case STOP:
          {
            cout << "Sorry, guy...\n";
            client.can_retry = false;
          }
      }
    }
  }
  return 0;
}

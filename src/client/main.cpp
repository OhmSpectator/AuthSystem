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
  while(1)
  {
    string message = console.ask_for_message();
    client.send_message((unsigned char*)(message.c_str()), message.length());
  }
  return 0;
}

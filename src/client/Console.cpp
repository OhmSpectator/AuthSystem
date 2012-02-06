#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

#include "Console.h"

using namespace std;

Console::Console()
{
  cout << "Welcome to Client console!\n";
}

Console::~Console()
{
}

const char* Console::get_server_addr()
{
  string result;
  bool correct_addr = false;
  while( !correct_addr )
  {
    cout << "Enter the Server address: \n";
    cin >> result;
    if( inet_aton( result.c_str(), NULL ) != 0 )
      correct_addr = true;
  }
  return result.c_str();
}

const char* Console::get_server_port()
{
  string result;
  bool correct_port = false;
  while( !correct_port )
  {
    cout << "Enter the Server port: \n";
    cin >> result;
    long buffer = atol( result.c_str() );
    if( buffer > 0 && buffer < 65538  )
      correct_port = true;
  }
  return result.c_str();
}

string Console::ask_for_message()
{
  string result;
  cout << "Enter a message for server: \n";
  cin >> result;
  return result;
}

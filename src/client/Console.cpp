#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include "../NetTypes.h"
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

login_password* Console::ask_for_logpass()
{
  login_password* result = new login_password;
  memset(result->login,0,20);
  memset(result->password,0,20);
  string login;
  string password;
  cout << "Enter login: \n";
  cin >> login;
  cout << "Enter password: \n";
  cin >> password;
  memcpy(result->login, login.c_str(),login.length());
  memcpy(result->password, password.c_str(), password.length());  
  return result;
}

string Console::ask_for_message()
{
  string result;
  cout << "Enter a message for server: \n";
  cin >> result;
  return result;
}

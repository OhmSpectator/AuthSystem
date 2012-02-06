#ifndef CONSOLE_H
#define CONSOLE_H

#include <string>

using namespace std;

class Console
{
  public:

  Console();
  ~Console();
  
  const char* get_server_addr();
  const char* get_server_port();
  string ask_for_message();  

};

#endif

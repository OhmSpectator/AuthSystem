#ifndef CONSOLE_H
#define CONSOLE_H

#include <string>
#include "../NetTypes.h"

using namespace std;

class Console
{
  public:

  Console();
  ~Console();
  
  const char* get_server_addr();
  const char* get_server_port();
  string ask_for_message();  
  login_password* ask_for_logpass();
};

#endif

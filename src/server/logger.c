#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logger.h"

int log_event(time_t time, event_type type, unsigned char* text, unsigned char* ip_string)
{

  FILE* log_file;
  log_file = fopen("log","a");
  unsigned char buffer[1000];
  strcpy(buffer, "[" );

  unsigned char* time_str;
  time_str = ctime(&time);
  strcpy(buffer + strlen("["), time_str);
  
  switch(type)
  {
    case DEBUG_MSG:
      strcpy(buffer + strlen("[") + strlen(time_str) - 1, "] DEBUG: ");
      strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: "), text);
      if(ip_string != NULL )
      {
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: ") + strlen(text), ". Source: " );
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: ") + strlen(text) + strlen(". Source: "), ip_string );
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: ") + strlen(text) + strlen(". Source: ") + strlen(ip_string) ] = '\0';
      }
      else
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: ") + strlen(text) ] = '\0';
      break;
    case INFO_MSG:
      strcpy(buffer + strlen("[") + strlen(time_str) - 1, "] INFO: ");
      strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] INFO: "), text);
      if(ip_string != NULL )
      {
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] INFO: ") + strlen(text), ". Source: " );
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] INFO: ") + strlen(text) + strlen(". Source: "), ip_string );
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] INFO: ") + strlen(text) + strlen(". Source: ") + strlen(ip_string) ] = '\0';
      }
      else
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] INFO: ") + strlen(text) ] = '\0';
      break;
    case ERROR_MSG:
      strcpy(buffer + strlen("[") + strlen(time_str) - 1, "] ERROR: ");
      strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: "), text);
      if(ip_string != NULL )
      {
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: ") + strlen(text), ". Source: " );
        strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: ") + strlen(text) + strlen(". Source: "), ip_string );
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: ") + strlen(text) + strlen(". Source: ") + strlen(ip_string) ] = '\0';
      }
      else
        buffer[strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: ") + strlen(text) ] = '\0';
      break;
  }

  printf("%s\n", buffer);

  fputs(buffer, log_file);
  fputc('\n', log_file);
  fclose(log_file);
}

logger* create_logger(const char* filename)
{
  logger* result;
  result = NULL;
  FILE* file;
  if((file = fopen(filename, "a+")) == NULL )
  {
    printf("DEBUG: log file creation error\n");
    return NULL;
  }

  result = (logger*)malloc(sizeof(logger));
  result->log_file = file;

  return result;
}

void stop_logger(logger* logger)
{ 
  fclose(logger->log_file);
  free(logger);
}


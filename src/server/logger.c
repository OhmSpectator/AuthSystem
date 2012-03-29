#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logger.h"

int log_event(time_t time, event_type type, unsigned char* text)
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
      buffer[strlen("[") + strlen(time_str) - 1 + strlen("] DEBUG: ") + strlen(text) ] = '\0';
      break;
    case INFO_MSG:
      strcpy(buffer + strlen("[") + strlen(time_str) - 1, "] INFO: ");
      strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] INFO: "), text);
      buffer[strlen("[") + strlen(time_str) - 1 + strlen("] INFO: ") + strlen(text) ] = '\0';
      break;
    case ERROR_MSG:
      strcpy(buffer + strlen("[") + strlen(time_str) - 1, "] ERROR: ");
      strcpy(buffer + strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: "), text);
      buffer[strlen("[") + strlen(time_str) - 1 + strlen("] ERROR: ") + strlen(text) ] = '\0';
      break;
  }

  printf("%s\n", buffer);

  if(fputs(buffer, log_file) == EOF)
    printf("DEBUG: can\'t cppend message\n");
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


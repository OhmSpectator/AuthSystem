#ifndef SERVER_LOGGER_H
#define SERVER_LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef enum
{
  DEBUG_MSG,
  INFO_MSG,
  ERROR_MSG
} event_type;

typedef struct logger_t
{
  FILE* log_file;
} logger;

int log_event(time_t time, event_type type, unsigned char* text);

logger* create_logger(const char* filename);

void stop_logger(logger* logger);

#endif

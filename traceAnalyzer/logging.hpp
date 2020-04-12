#ifndef INTRIGUER_LOGGING_H_
#define INTRIGUER_LOGGING_H_

#include <stdio.h>
#include <stdlib.h>
#include <cstdarg>
#include <string>

void log(const char* tag, const std::string &msg);

void LOG_DEBUG(const std::string &msg);

#endif 

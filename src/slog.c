#include "slog.h"

const char slog_level_char[] = { 'V', 'D', 'I', 'W', 'E', 'F' };
int slog_level = LOG_LEVEL_VERBOSE;
FILE *slog_file = NULL;

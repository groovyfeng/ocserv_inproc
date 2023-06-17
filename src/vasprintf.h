#ifndef OC_VASPRINTF_H
#define OC_VASPRINTF_H

#include "config.h"

#ifndef HAVE_VASPRINTF
int _ocserv_vasprintf(char **strp, const char *fmt, va_list ap);
#define vasprintf _ocserv_vasprintf
#else
#include <stdio.h>
#endif

#endif

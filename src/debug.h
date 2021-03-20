/*
    Ophidia Server
    Copyright (C) 2012-2021 CMCC Foundation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef DEBUG_H
#define DEBUG_H

#include <stdarg.h>
#include <stdio.h>

#include <unistd.h>		/* defines _POSIX_THREADS if pthreads are available */
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <pthread.h>
#endif

#define LOG_RAW			0

#define LOG_ERROR 		1
#define LOG_INFO 		2
#define LOG_WARNING 	3
#define LOG_DEBUG		4

#define LOG_ERROR_T 	11
#define LOG_INFO_T		12
#define LOG_WARNING_T 	13
#define LOG_DEBUG_T		14

#if defined(NDEBUG) && defined(__GNUC__)
/* gcc's cpp has extensions; it allows for macros with a variable number of
   arguments. We use this extension here to preprocess pmesg away. */
#define pmesg(level, source, line_number, format, args...) ((void)0)
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#define pmesg_save(flag, level, source, line_number, format, args...) ((void)0)
#endif
#else
void pmesg(int level, const char *source, long int line_number, const char *format, ...);
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
void pmesg_safe(pthread_mutex_t * flag, int level, const char *source, long int line_number, const char *format, ...);
#endif
/* print a message, if it is considered significant enough.
      Adapted from [K&R2], p. 174 */
#endif

int get_debug_level();
void set_debug_level(int level);
void set_log_file(FILE * file);

#endif				/* DEBUG_H */

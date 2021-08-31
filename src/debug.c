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

#include "debug.h"
#include <string.h>
#include <time.h>

#define CTIME_BUF 32

//extern int msglevel; /* the higher, the more messages... */
int msglevel = LOG_INFO;	/* the higher, the more messages... */
FILE *log_file = 0;

#if defined(NDEBUG) && defined(__GNUC__)
/* Nothing. pmesg has been "defined away" in debug.h already. */
#else

void pmesg(int level, const char *source, long int line_number, const char *format, ...)
{
#ifdef NDEBUG
	/* Empty body, so a good compiler will optimise calls to pmesg away */
#else
	va_list args;
	char log_type[10];
	int new_msglevel = msglevel % 10;
	if (level > new_msglevel)
		return;

	switch (level) {
		case LOG_ERROR:
			sprintf(log_type, "ERROR");
			break;
		case LOG_INFO:
			sprintf(log_type, "INFO");
			break;
		case LOG_WARNING:
			sprintf(log_type, "WARNING");
			break;
		case LOG_DEBUG:
			sprintf(log_type, "DEBUG");
			break;
		case LOG_RAW:
			*log_type = 0;
			break;
		default:
			sprintf(log_type, "UNKNOWN");
			break;
	}

	if (level) {
		if (msglevel > 10) {
			time_t t1 = time(NULL);
			char s[CTIME_BUF];
			ctime_r(&t1, s);
			s[strlen(s) - 1] = 0;	// remove \n
			fprintf(log_file ? log_file : stderr, "[%s][%s][%s][%ld]\t", s, log_type, source, line_number);
		} else if (level)
			fprintf(log_file ? log_file : stderr, "[%s][%s][%ld]\t", log_type, source, line_number);
	}

	va_start(args, format);
	vfprintf(log_file ? log_file : stderr, format, args);
	va_end(args);
	fflush(log_file ? log_file : stderr);

#endif				/* NDEBUG */
}

void pmesg_safe(pthread_mutex_t * flag, int level, const char *source, long int line_number, const char *format, ...)
{
#ifdef NDEBUG
	/* Empty body, so a good compiler will optimise calls to pmesg away */
#else
	va_list args;
	char log_type[10];
	int new_msglevel = msglevel % 10;
	if (level > new_msglevel)
		return;

	switch (level) {
		case LOG_ERROR:
			sprintf(log_type, LOG_ERROR_MESSAGE);
			break;
		case LOG_INFO:
			sprintf(log_type, LOG_INFO_MESSAGE);
			break;
		case LOG_WARNING:
			sprintf(log_type, LOG_WARNING_MESSAGE);
			break;
		case LOG_DEBUG:
			sprintf(log_type, LOG_DEBUG_MESSAGE);
			break;
		case LOG_RAW:
			*log_type = 0;
			break;
		default:
			sprintf(log_type, LOG_UNKNOWN_MESSAGE);
			break;
	}

	if (flag)
		pthread_mutex_lock(flag);

	if (level) {
		if (msglevel > 10) {
			time_t t1 = time(NULL);
			char s[CTIME_BUF];
			ctime_r(&t1, s);
			s[strlen(s) - 1] = 0;	// remove \n
			fprintf(log_file ? log_file : stderr, "[%s][%s][%s][%ld]\t", s, log_type, source, line_number);
		} else
			fprintf(log_file ? log_file : stderr, "[%s][%s][%ld]\t", log_type, source, line_number);
	}

	va_start(args, format);
	vfprintf(log_file ? log_file : stderr, format, args);
	va_end(args);
	fflush(log_file ? log_file : stderr);

	if (flag)
		pthread_mutex_unlock(flag);

#endif				/* NDEBUG */
}

#endif				/* NDEBUG && __GNUC__ */

int get_debug_level()
{
	return msglevel % 10;
}

void set_debug_level(int level)
{
	msglevel = level;
}

void set_log_file(FILE * file)
{
	log_file = file;
}

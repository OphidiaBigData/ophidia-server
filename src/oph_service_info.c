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

#include <oph_service_info.h>

#include <sys/time.h>

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
extern pthread_mutex_t service_flag;
#endif

void oph_service_info_thread_incr(oph_service_info * service_info)
{
	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->current_thread_number++;
		if (service_info->peak_thread_number < service_info->current_thread_number) {
			service_info->peak_thread_number = service_info->current_thread_number;
			struct timeval tv;
			gettimeofday(&tv, NULL);
			service_info->peak_thread_number_timestamp = tv.tv_sec;
		}
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}
}

void oph_service_info_thread_decr(oph_service_info * service_info)
{
	if (service_info) {
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_lock(&service_flag);
#endif
		service_info->current_thread_number--;
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
		pthread_mutex_unlock(&service_flag);
#endif
	}
}

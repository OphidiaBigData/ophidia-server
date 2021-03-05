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

#ifndef OPH_SSH_SUBMIT_H
#define OPH_SSH_SUBMIT_H

#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <pthread.h>
#endif

#include "oph_gather.h"

#define OPH_LIBSSH_OK 0
#define OPH_LIBSSH_ERROR 1

#ifdef SSH_SUPPORT
static int waitsocket(int socket_fd, LIBSSH2_SESSION * session);
#endif

int oph_ssh_submit(const char *cmd);

#endif				/* OPH_SSH_SUBMIT_H */

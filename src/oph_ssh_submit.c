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

#include <sys/types.h>
#include <sys/wait.h>

#ifdef SSH_SUPPORT
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#else
#define OPH_LIBSSH_SEPARATOR '\"'
#define OPH_LIBSSH_ESCAPE '\\'
#define OPH_LIBSSH_SYSTEM_COMMAND "ssh %s %c%s%c >/dev/null 2>&1 </dev/null"
#endif

#include "oph_ssh_submit.h"

extern pthread_mutex_t global_flag;
extern pthread_mutex_t libssh2_flag;
extern char *oph_ip_target_host;
extern char oph_subm_ssh;
extern char *oph_subm_user;
extern char *oph_subm_user_publk;
extern char *oph_subm_user_privk;

#ifdef SSH_SUPPORT
int waitsocket(int socket_fd, LIBSSH2_SESSION * session)
{
	struct timeval timeout;
	int rc;
	fd_set fd;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;
	int dir;

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	FD_ZERO(&fd);

	FD_SET(socket_fd, &fd);

	dir = libssh2_session_block_directions(session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;

	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		writefd = &fd;

	rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

	return rc;
}
#else
int _system(const char *command)
{
	if (!command)
		return -1;

	pid_t childPid;
	int status;

	switch (childPid = fork()) {

		case -1:
			status = -1;
			break;

		case 0:
			execl("/bin/sh", "sh", "-c", command, (char *) NULL);
			_exit(127);

		default:
			while (waitpid(childPid, &status, 0) == -1) {
				if (errno != EINTR) {
					status = -1;
					break;
				}
			}
			break;
	}

	return status;
}
#endif

int oph_ssh_submit(const char *cmd)
{
	if (!cmd || !strlen(cmd)) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Null pointer\n");
		return OPH_LIBSSH_ERROR;
	}
#ifdef SSH_SUPPORT

	int sock;
	struct sockaddr_in sin;
	struct addrinfo hints, *result;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int rc;
	int exitcode;
	char *exitsignal = (char *) "none";
	int bytecount = 0;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	result = NULL;
	rc = getaddrinfo(oph_ip_target_host, NULL, &hints, &result);
	if (rc != 0) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Unable to resolve address from target hostname: %s\n", gai_strerror(rc));
		return OPH_LIBSSH_ERROR;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = ((struct sockaddr_in *) result->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(result);
	if (connect(sock, (struct sockaddr *) (&sin), sizeof(struct sockaddr_in)) != 0) {
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Failed to connect to submission host\n");
		return OPH_LIBSSH_ERROR;
	}

	pthread_mutex_lock(&libssh2_flag);	// Lock the access to SSH library
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "SSH2 library locked\n");

	rc = libssh2_init(0);
	if (rc != 0) {
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "libssh2 initialization failed (%d)\n", rc);
		return OPH_LIBSSH_ERROR;
	}

	char *errmsg = NULL;
	int errmsg_len = 0;

	session = libssh2_session_init();
	if (!session) {
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		libssh2_exit();
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Failed to init ssh session\n");
		return OPH_LIBSSH_ERROR;
	}

	libssh2_session_set_blocking(session, 0);

	while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		libssh2_session_last_error(session, &errmsg, &errmsg_len, 1);
		libssh2_session_disconnect(session, "Session disconnected");
		libssh2_session_free(session);
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		libssh2_exit();
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Failure establishing SSH session (%d): %s\n", rc, errmsg ? errmsg : "no additional info");
		if (errmsg)
			free(errmsg);
		return OPH_LIBSSH_ERROR;
	}

	while ((rc = libssh2_userauth_publickey_fromfile(session, oph_subm_user, oph_subm_user_publk, oph_subm_user_privk, "")) == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		libssh2_session_last_error(session, &errmsg, &errmsg_len, 1);
		libssh2_session_disconnect(session, "Session disconnected");
		libssh2_session_free(session);
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		libssh2_exit();
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Authentication by public key failed (%d): %s\n", rc, errmsg ? errmsg : "no additional info");
		if (errmsg)
			free(errmsg);
		return OPH_LIBSSH_ERROR;
	}

	while ((channel = libssh2_channel_open_session(session)) == NULL && libssh2_session_last_error(session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	}
	if (channel == NULL) {
		libssh2_session_last_error(session, &errmsg, &errmsg_len, 1);
		libssh2_session_disconnect(session, "Session disconnected");
		libssh2_session_free(session);
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		libssh2_exit();
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during opening channel session: %s\n", errmsg ? errmsg : "no additional info");
		if (errmsg)
			free(errmsg);
		return OPH_LIBSSH_ERROR;
	}
	while ((rc = libssh2_channel_exec(channel, cmd)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(sock, session);
	}
	if (rc) {
		libssh2_session_last_error(session, &errmsg, &errmsg_len, 1);
		libssh2_channel_free(channel);
		libssh2_session_disconnect(session, "Session disconnected");
		libssh2_session_free(session);
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		libssh2_exit();
		pthread_mutex_unlock(&libssh2_flag);
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Error during sending commands over ssh channel (%d): %s\n", rc, errmsg ? errmsg : "no additional info");
		if (errmsg)
			free(errmsg);
		return OPH_LIBSSH_ERROR;
	}

	int flag = 0;
	for (;;) {
		int rc;
		do {
			char buffer[0x4000];
			rc = libssh2_channel_read(channel, buffer, sizeof(buffer));

			if (rc > 0) {
				int i;
				bytecount += rc;
				if (!flag) {
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "ssh submission returned:\n");
					flag = 1;
				}
				for (i = 0; i < rc; ++i)
					pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "%c\n", buffer[i]);
			} else if (rc != LIBSSH2_ERROR_EAGAIN)
				pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "ssh channel read returned %d\n", rc);
		}
		while (rc > 0);

		if (rc == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(sock, session);
		} else
			break;
	}
	exitcode = 127;
	while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);

	if (rc == 0) {
		exitcode = libssh2_channel_get_exit_status(channel);
		libssh2_channel_get_exit_signal(channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);
	}

	if (exitsignal)
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "ssh got signal %s\n", exitsignal);
	else
		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "ssh exit code %d with: bytecount %d\n", exitcode, bytecount);

	libssh2_channel_free(channel);
	channel = NULL;

	libssh2_session_disconnect(session, "Session ended normally");
	libssh2_session_free(session);
#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Session ended normally\n");

	libssh2_exit();

	pthread_mutex_unlock(&libssh2_flag);	// Release the lock for SSH library
	pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "SSH2 library unlocked\n");

#else

	int result = 0;

	if (oph_subm_ssh) {

		size_t i, j, size_cmd = strlen(cmd);
		char scmd[2 * size_cmd];
		for (i = j = 0; i < size_cmd; ++i, ++j) {
			if (cmd[i] == OPH_LIBSSH_SEPARATOR) {
				scmd[j++] = OPH_LIBSSH_ESCAPE;
			}
			scmd[j] = cmd[i];
		}
		scmd[j] = 0;

		char rcmd[25 + strlen(oph_ip_target_host) + j];
		sprintf(rcmd, OPH_LIBSSH_SYSTEM_COMMAND, oph_ip_target_host, OPH_LIBSSH_SEPARATOR, scmd, OPH_LIBSSH_SEPARATOR);

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute:\n%s\n", rcmd);
		result = _system(rcmd);

	} else {

		pmesg_safe(&global_flag, LOG_DEBUG, __FILE__, __LINE__, "Execute:\n%s\n", cmd);
		result = _system(cmd);
	}

	if (result) {
		pmesg_safe(&global_flag, LOG_ERROR, __FILE__, __LINE__, "Failed to submit the command %s\n", cmd);
		return OPH_LIBSSH_ERROR;
	}
#endif

	return OPH_LIBSSH_OK;
}

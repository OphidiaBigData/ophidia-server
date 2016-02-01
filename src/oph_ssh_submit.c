/*
    Ophidia Server
    Copyright (C) 2012-2016 CMCC Foundation

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

#include <libssh2.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include "oph_ssh_submit.h"

extern pthread_mutex_t global_flag;
extern pthread_mutex_t libssh2_flag;
extern char* oph_ip_target_host;
extern char* oph_subm_user;
extern char* oph_subm_user_publk;
extern char* oph_subm_user_privk;

int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
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

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

int oph_ssh_submit(const char* cmd)
{
    unsigned long hostaddr;
    int sock;
    struct sockaddr_in sin;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    int rc;
    int exitcode;
    char *exitsignal=(char *)"none";
    int bytecount = 0;

    pthread_mutex_lock(&libssh2_flag);
    rc = libssh2_init (0);
    pthread_mutex_unlock(&libssh2_flag);
    if (rc != 0) {
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "libssh2 initialization failed (%d)\n", rc);
        return OPH_LIBSSH_ERROR;
    }

    hostaddr = inet_addr(oph_ip_target_host);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Failed to connect to submission host\n");
        return OPH_LIBSSH_ERROR;
    }

    session = libssh2_session_init();
    if (!session){
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Failed to init ssh sessione\n");
        return OPH_LIBSSH_ERROR;
    }

    libssh2_session_set_blocking(session, 0);

    while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
    if (rc) {
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Failure establishing SSH session: %d\n", rc);
        return OPH_LIBSSH_ERROR;
    }

        while ((rc = libssh2_userauth_publickey_fromfile(session, oph_subm_user, oph_subm_user_publk, oph_subm_user_privk,"")) == LIBSSH2_ERROR_EAGAIN);
        if (rc) {
		pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Authentication by public key failed\n");
    		libssh2_session_disconnect(session, "Session disconnected");
    		libssh2_session_free(session);
		#ifdef WIN32
    			closesocket(sock);
		#else
    			close(sock);
		#endif
    		libssh2_exit();
        	return OPH_LIBSSH_ERROR;
        }

    while( (channel = libssh2_channel_open_session(session)) == NULL && libssh2_session_last_error(session,NULL,NULL,0) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( channel == NULL )
    {
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error during opening session channel\n");
        return OPH_LIBSSH_ERROR;
    }
    while( (rc = libssh2_channel_exec(channel, cmd)) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( rc != 0 )
    {
	pmesg_safe(&global_flag,LOG_ERROR, __FILE__,__LINE__, "Error during opening session channel\n");
        return OPH_LIBSSH_ERROR;
    }
    int flag = 0;
    for( ;; )
    {
        int rc;
        do
        {
            char buffer[0x4000];
            rc = libssh2_channel_read( channel, buffer, sizeof(buffer) );
	    
            if( rc > 0 )
            {
                int i;
                bytecount += rc;
                if(!flag){
			pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "ssh submission returned:\n");
	    		flag = 1;
		}
                for( i=0; i < rc; ++i ) pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "%c\n", buffer[i]);
            }
            else if( rc != LIBSSH2_ERROR_EAGAIN ) pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "ssh channel read returned %d\n", rc);
        }
        while( rc > 0 );

        if( rc == LIBSSH2_ERROR_EAGAIN )
        {
            waitsocket(sock, session);
        }
        else
            break;
    }
    exitcode = 127;
    while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )
        waitsocket(sock, session);

    if( rc == 0 )
    {
        exitcode = libssh2_channel_get_exit_status( channel );
        libssh2_channel_get_exit_signal(channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);
    }

    if (exitsignal)
	pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "ssh got signal %s\n", exitsignal);
    else 
	pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "ssh exit code %d with: bytecount %d\n", exitcode, bytecount);

    libssh2_channel_free(channel);
    channel = NULL;

    libssh2_session_disconnect(session,"Session ended normally");
    libssh2_session_free(session);

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    pmesg_safe(&global_flag,LOG_INFO, __FILE__,__LINE__, "Session ended normally\n");

    libssh2_exit();

        return OPH_LIBSSH_OK;
}


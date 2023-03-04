/*
    Ophidia Server
    Copyright (C) 2012-2022 CMCC Foundation

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

#include "oph_gather.h"
#include "oph.nsmap"

#include <unistd.h>
#if defined(_POSIX_THREADS) || defined(_SC_THREADS)
#include <pthread.h>
#endif
#include <signal.h>

#define OPH_DEFAULT_NLOOPS 1
#define OPH_DEFAULT_QUERY "OPH_NULL"
#define CLIENT_USERID "oph-test"
#define CLIENT_PASSWORD "abcd"

#include <inttypes.h>
#include <string.h>

int base64encode(const void *data_buf, size_t dataLength, char *result, size_t resultSize)
{
	const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *data = (const uint8_t *) data_buf;
	size_t resultIndex = 0;
	size_t x;
	uint32_t n = 0;
	int padCount = dataLength % 3;
	uint8_t n0, n1, n2, n3;

	/* increment over the length of the string, three characters at a time */
	for (x = 0; x < dataLength; x += 3) {
		/* these three 8-bit (ASCII) characters become one 24-bit number */
		n = ((uint32_t) data[x]) << 16;	//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

		if ((x + 1) < dataLength)
			n += ((uint32_t) data[x + 1]) << 8;	//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

		if ((x + 2) < dataLength)
			n += data[x + 2];

		/* this 24-bit number gets separated into four 6-bit numbers */
		n0 = (uint8_t) (n >> 18) & 63;
		n1 = (uint8_t) (n >> 12) & 63;
		n2 = (uint8_t) (n >> 6) & 63;
		n3 = (uint8_t) n & 63;

		/*
		 * if we have one byte available, then its encoding is spread
		 * out over two characters
		 */
		if (resultIndex >= resultSize)
			return 1;	/* indicate failure: buffer too small */
		result[resultIndex++] = base64chars[n0];
		if (resultIndex >= resultSize)
			return 1;	/* indicate failure: buffer too small */
		result[resultIndex++] = base64chars[n1];

		/*
		 * if we have only two bytes available, then their encoding is
		 * spread out over three chars
		 */
		if ((x + 1) < dataLength) {
			if (resultIndex >= resultSize)
				return 1;	/* indicate failure: buffer too small */
			result[resultIndex++] = base64chars[n2];
		}

		/*
		 * if we have all three bytes available, then their encoding is spread
		 * out over four characters
		 */
		if ((x + 2) < dataLength) {
			if (resultIndex >= resultSize)
				return 1;	/* indicate failure: buffer too small */
			result[resultIndex++] = base64chars[n3];
		}
	}

	/*
	 * create and add padding that is required if we did not have a multiple of 3
	 * number of characters available
	 */
	if (padCount > 0) {
		for (; padCount < 3; padCount++) {
			if (resultIndex >= resultSize)
				return 1;	/* indicate failure: buffer too small */
			result[resultIndex++] = '=';
		}
	}
	if (resultIndex >= resultSize)
		return 1;	/* indicate failure: buffer too small */
	result[resultIndex] = 0;
	return 0;		/* indicate success */
}

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66, 66, 66, 63, 52, 53,
	54, 55, 56, 57, 58, 59, 60, 61, 66, 66, 66, 65, 66, 66, 66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 66, 66, 66, 66, 66, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66
};

int base64decode(const char *in, size_t inLen, char *out, size_t * outLen)
{
	const char *end = in + inLen;
	char iter = 0;
	size_t buf = 0, len = 0;

	while (in < end) {
		unsigned char c = d[(int) (*in++)];

		switch (c) {
			case WHITESPACE:
				continue;	/* skip whitespace */
			case INVALID:
				return 1;	/* invalid input, return error */
			case EQUALS:	/* pad character, end of data */
				in = end;
				continue;
			default:
				buf = buf << 6 | c;
				iter++;	// increment the number of iteration
				/* If the buffer is full, split it into bytes */
				if (iter == 4) {
					if ((len += 3) > *outLen)
						return 1;	/* buffer overflow */
					(*out) = (buf >> 16) & 255;
					out++;
					(*out) = (buf >> 8) & 255;
					out++;
					(*out) = buf & 255;
					out++;
					buf = 0;
					iter = 0;

				}
		}
	}

	if (iter == 3) {
		if ((len += 2) > *outLen)
			return 1;	/* buffer overflow */
		(*out) = (buf >> 10) & 255;
		out++;
		(*out) = (buf >> 2) & 255;
		out++;
	} else if (iter == 2) {
		if (++len > *outLen)
			return 1;	/* buffer overflow */
		(*out) = (buf >> 4) & 255;
		out++;
	}

	*outLen = len;		/* modify to reflect the actual output size */

	return 0;
}

int b64decode(const char *query, char **new_query)
{
	if (!query || !new_query)
		return 1;
	size_t len = OPH_MAX_PROGRAM_SIZE;
	char *_query = (char *) malloc(len * sizeof(char));
	if (!_query) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Memory allocation error");
		return 1;
	}
	char *query_ = _query;
	int result_code = base64decode(query, strlen(query), _query, &len);
	if (!result_code) {
		if (len + 1 < OPH_MAX_PROGRAM_SIZE)
			*(query_ + len) = 0;
		else {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "Space not available");
			return -2;
		}
	}
	*new_query = query_;
	return result_code;
}

int CRYPTO_thread_setup();
void CRYPTO_thread_cleanup();
void sigpipe_handle(int);

void cleanup(struct soap *soap)
{
	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);
	CRYPTO_thread_cleanup();
}

int oph_execute(struct soap *soap, char *server, xsd__string query, int b64)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Sending request to %s\n", server);
	struct oph__ophResponse response;
	if (soap_call_oph__ophExecuteMain(soap, server, "", query, &response)) {
		soap_print_fault(soap, stderr);
		return 1;
	}
	if (b64 && !response.error && response.response) {
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Encoding the response\n");
		char result[OPH_MAX_PROGRAM_SIZE], *_result = result;
		if (base64encode(response.response, strlen(response.response), _result, OPH_MAX_PROGRAM_SIZE))
			return 1;
		printf("Return code: 0\nJobID: %s\nResponse: %s\n", response.jobid ? response.jobid : "", result);
	} else
		printf("Return code: %ld\nJobID: %s\nResponse: %s\n", response.error, response.error || !response.jobid ? "" : response.jobid, response.error
		       || !response.response ? "" : response.response);
	return response.error;
}

int oph_notify(struct soap *soap, char *server, xsd__int jobid, enum oph__oph_odb_job_status status)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Sending notification to %s\n", server);
	xsd__int response;
	char data[OPH_MAX_STRING_SIZE];
	snprintf(data, OPH_MAX_STRING_SIZE, "jobid=%d;status=%d;parentid=0;taskindex=0;lighttaskindex=0;", (int) jobid, status);
	if (soap_call_oph__oph_notify(soap, server, "", data, NULL, &response)) {
		soap_print_fault(soap, stderr);
		return 1;
	}
	printf("Return code: %ld\nJobID: \nResponse: \n", response);
	return response;
}

int oph_get_configuration(struct soap *soap, char *server, xsd__string key)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "Sending request to %s\n", server);
	char tmp[OPH_MAX_STRING_SIZE];
	snprintf(tmp, OPH_MAX_STRING_SIZE, "operator=oph_get_config;key=%s;", key);
	struct oph__ophResponse response;
	if (soap_call_oph__ophExecuteMain(soap, server, "", tmp, &response)) {
		soap_print_fault(soap, stderr);
		return 1;
	}
	printf("Return code: %ld\nJobID: \nResponse: %s\n", response.error, response.error || !response.response ? "" : response.response);
	return response.error;
}

int main(int argc, char *argv[])
{
	struct soap soap;

	char _query[OPH_MAX_PROGRAM_SIZE];
	char server[OPH_MAX_STRING_SIZE];
	int ch, msglevel = LOG_ERROR, job = 0, b64 = 0;
	char *query = OPH_DEFAULT_QUERY, *host = OPH_DEFAULT_HOST, *port = OPH_DEFAULT_PORT, *username = CLIENT_USERID, *password = CLIENT_PASSWORD, *key = 0, *filename = 0;
	enum oph__oph_odb_job_status status = OPH_ODB_STATUS_UNKNOWN;

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER2);

	while ((ch = getopt(argc, argv, "bc:df:h:j:k:p:q:u:vwxz")) != -1) {
		switch (ch) {
			case 'b':
				b64 = 1;
				break;
			case 'c':
				key = optarg;
				break;
			case 'd':
				msglevel = LOG_DEBUG;
				break;
			case 'f':
				filename = optarg;
				break;
			case 'h':
				host = optarg;
				break;
			case 'j':
				job = atoi(optarg);
				break;
			case 'k':
				password = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'q':
				query = optarg;
				break;
			case 'u':
				username = optarg;
				break;
			case 'v':
				return 0;
				break;
			case 'w':
				if (msglevel < LOG_WARNING)
					msglevel = LOG_WARNING;
				break;
			case 'x':
				fprintf(stdout, "%s", OPH_WARRANTY);
				return 0;
			case 'z':
				fprintf(stdout, "%s", OPH_CONDITIONS);
				return 0;
			default:
				fprintf(stdout, "Usage:\noph_client -f <JSON Request file> [-d] [-p <port>] [-h <host>] [-u <username>] [-v] [-w]\n");
				return 0;
		}
	}
	set_debug_level(msglevel + 10);

	if (filename) {
		FILE *fp = fopen(filename, "r");
		if (!fp) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "File name is wrong\n");
			return 2;
		}
		fseek(fp, 0, SEEK_END);
		long size = ftell(fp);
		rewind(fp);
		size_t r = fread(_query, size, 1, fp);
		fclose(fp);
		if (!r) {
			pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON file cannot be read\n");
			return 4;
		}

		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Received file:\n%s\n", _query);

		if (b64) {
			char *new_query = NULL;
			if (b64decode(_query, &new_query)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "JSON file cannot be decoded\n");
				return 3;
			}
			if (new_query) {
				snprintf(_query, OPH_MAX_PROGRAM_SIZE, "%s", new_query);
				free(new_query);
			}
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "JSON file:\n%s\n", _query);
		query = _query;
	} else if (query && strcmp(query, OPH_DEFAULT_QUERY)) {
		if (b64) {
			char *new_query = NULL;
			if (b64decode(query, &new_query)) {
				pmesg(LOG_ERROR, __FILE__, __LINE__, "Request cannot be decoded\n");
				return 3;
			}
			if (new_query) {
				snprintf(_query, OPH_MAX_PROGRAM_SIZE, "%s", new_query);
				free(new_query);
			}
			query = _query;
		}
		pmesg(LOG_DEBUG, __FILE__, __LINE__, "Request: %s\n", query);
	} else {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Current version support option -f or -q only... use: oph_client -f <JSON Request file>\n");
		return 1;
	}

	/* Need SIGPIPE handler on Unix/Linux systems to catch broken pipes: */
	signal(SIGPIPE, sigpipe_handle);

#ifdef WITH_OPENSSL
	/* Init SSL */
	soap_ssl_init();
#endif
	if (CRYPTO_thread_setup()) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "Cannot setup thread mutex for OpenSSL\n");
		exit(1);
	}
	soap_init(&soap);
#ifdef WITH_OPENSSL
	/* Init gSOAP context */
	if (soap_ssl_client_context(&soap, SOAP_TLSv1_2 | SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, NULL, NULL, NULL)) {
		pmesg(LOG_ERROR, __FILE__, __LINE__, "SSL Server Context Error\n");
		soap_print_fault(&soap, stderr);
		cleanup(&soap);
		exit(1);
	}
#endif
	soap.connect_timeout = 60;	/* try to connect for 1 minute */
	soap.send_timeout = soap.recv_timeout = 3600;	/* if I/O stalls, then timeout after 3600 seconds */

	snprintf(server, OPH_MAX_STRING_SIZE, "%s://%s:%s", OPH_DEFAULT_PROTOCOL, host, port);

	int return_code = 0;
	soap.userid = username;	// Username has to set for each serve
	soap.passwd = password;	// Password has to set for each serve
	if (key)
		return_code = oph_get_configuration(&soap, server, key);
	else if (job)
		return_code = oph_notify(&soap, server, job, status);
	else
		return_code = oph_execute(&soap, server, query, b64);

	cleanup(&soap);
	return return_code;
}

/******************************************************************************\
 *
 *	OpenSSL
 *
\******************************************************************************/

#ifdef WITH_OPENSSL

#if defined(WIN32)
#define MUTEX_TYPE		HANDLE
#define MUTEX_SETUP(x)		(x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x)	CloseHandle(x)
#define MUTEX_LOCK(x)		WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)	ReleaseMutex(x)
#define THREAD_ID		GetCurrentThreadId()
#elif defined(_POSIX_THREADS) || defined(_SC_THREADS)
#define MUTEX_TYPE		pthread_mutex_t
#define MUTEX_SETUP(x)		pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)	pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)		pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)	pthread_mutex_unlock(&(x))
#define THREAD_ID		pthread_self()
#else
#error "You must define mutex operations appropriate for your platform"
#error	"See OpenSSL /threads/th-lock.c on how to implement mutex on your platform"
#endif

struct CRYPTO_dynlock_value {
	MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf;

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
	if (!file || !line)
		pmesg(LOG_ERROR, __FILE__, __LINE__, "");
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value *) malloc(sizeof(struct CRYPTO_dynlock_value));
	if (value)
		MUTEX_SETUP(value->mutex);
	return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if (!file || !line)
		pmesg(LOG_ERROR, __FILE__, __LINE__, "");
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(l->mutex);
	else
		MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if (!file || !line)
		pmesg(LOG_ERROR, __FILE__, __LINE__, "");
	MUTEX_CLEANUP(l->mutex);
	free(l);
}

void locking_function(int mode, int n, const char *file, int line)
{
	if (!file || !line)
		pmesg(LOG_ERROR, __FILE__, __LINE__, "");
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function()
{
	return (unsigned long) THREAD_ID;
}

int CRYPTO_thread_setup()
{
	int i;
	mutex_buf = (MUTEX_TYPE *) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return SOAP_EOM;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{
	int i;
	if (!mutex_buf)
		return;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
}

#else

/* OpenSSL not used, e.g. GNUTLS is used */

int CRYPTO_thread_setup()
{
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{
}

#endif

/******************************************************************************\
 *
 *	SIGPIPE
 *
\******************************************************************************/

void sigpipe_handle(int x)
{
	pmesg(LOG_DEBUG, __FILE__, __LINE__, "CALLED oph_signal_handler; catched signal nr %d\n", x);
}

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

#include "gsi.h"
#include "stdio.h"
#include "oph_gather.h"
#include "oph.nsmap"

/* authorization callback prototype */
int gsi_authorization_callback(struct soap *soap, char *distinguished_name);

/* credential renewal callback */
int gsi_plugin_credential_renew_callback(struct soap *soap, int lifetime);

#define PLUGIN_DEFAULT_QUERY "operator=oph_list;exec_mode=sync;"

int main(int argc, char **argv)
{
	struct soap soap;
	int rc;
	unsigned short int port = PLUGIN_DEFAULT_PORT;
	char *server = PLUGIN_DEFAULT_HOSTNAME, *query = PLUGIN_DEFAULT_QUERY;
	char connection[128];
	int c, result = 1;
	static char *USAGE = "\nUSAGE:\noph_client -s hostname -p port- q query -v\n";

	fprintf(stdout, "%s", OPH_VERSION);
	fprintf(stdout, "%s", OPH_DISCLAIMER2);

	while ((c = getopt(argc, argv, "s:p:q:vxz")) != -1) {
		switch (c) {
			case 's':
				server = optarg;
				break;
			case 'p':
				port = (unsigned short int) atoi(optarg);
				break;
			case 'q':
				query = optarg;
				break;
			case 'v':
				fprintf(stdout, "%s", OPH_VERSION);
				exit(0);
			case 'x':
				fprintf(stdout, "%s", OPH_WARRANTY);
				exit(0);
			case 'z':
				fprintf(stdout, "%s", OPH_CONDITIONS);
				exit(0);
			default:
				fprintf(stderr, "\n%s\n", USAGE);
				exit(1);
		}
	}

	snprintf(connection, 128, "%s://%s:%d", OPH_DEFAULT_PROTOCOL, server, port);

	globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

	soap_init(&soap);

	/* now we register the GSI plugin */

	if (soap_register_plugin(&soap, globus_gsi)) {
		soap_print_fault(&soap, stderr);
		/* deallocate gsoap run-time environment */
		soap_destroy(&soap);
		soap_end(&soap);
		soap_done(&soap);
		/* deactivate globus module */
		globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
		exit(EXIT_FAILURE);
	}
	/* setup of authorization and credential renewal callbacks */
	gsi_authorization_callback_register(&soap, gsi_authorization_callback);
	gsi_credential_renew_callback_register(&soap, gsi_plugin_credential_renew_callback);

	/* we begin acquiring our credential */
	rc = gsi_acquire_credential(&soap);
	if (rc < 0) {
		/* deallocate gsoap run-time environment */
		soap_destroy(&soap);
		soap_end(&soap);
		soap_done(&soap);
		/* deactivate globus module */
		globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
		exit(EXIT_FAILURE);
	}

	/* setup of GSI channel */
	gsi_set_replay(&soap, GLOBUS_TRUE);
	gsi_set_sequence(&soap, GLOBUS_TRUE);
	gsi_set_confidentiality(&soap, GLOBUS_TRUE);
	gsi_set_integrity(&soap, GLOBUS_TRUE);

	/* Timeout after 2 minutes stall on send/recv */
	gsi_set_recv_timeout(&soap, 120);
	gsi_set_send_timeout(&soap, 120);

	soap.userid = NULL;
	soap.passwd = NULL;

	struct oph__ophResponse response;
	if (soap_call_oph__ophExecuteMain(&soap, connection, "", query, &response) == SOAP_OK) {
		printf("Return: %d\nJobID: %s\nResponse: %s\n", (int) response.error, response.error || !response.jobid ? "" : response.jobid, response.error
		       || !response.response ? "" : response.response);
		result = response.error;
	} else
		soap_print_fault(&soap, stderr);

	/* deallocate gsoap run-time environment */
	soap_destroy(&soap);
	soap_end(&soap);
	soap_done(&soap);

	/* deactivate globus module */
	globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);

	return result;
}


/*
 * ! \fn gsi_plugin_credential_renew_callback(struct soap *soap)
 * 
 * \brief This function is an example of a credential renewal callback
 * 
 * This function is an example of a credential renewal callback 
 * 
 * \param struct soap *soap The current gSOAP runtime environment 
 * \param int lifetime The remaining lifetime of our credential (in seconds);
 *		       if > 0 our credential is still valid, if <= 0 our credential has expired 
 * 
 * \return  0 on success, 1 on error
 *
 */
int gsi_plugin_credential_renew_callback(struct soap *soap, int lifetime)
{
	char proxy_pwd[] = "your_proxy_pwd";
	char grid_proxy_init_args[] = "-valid 2:0";
	char *globus_location;
	char init[] = "/bin/grid-proxy-init -pwstdin ";
	char destroy[] = "/bin/grid-proxy-destroy";
	int rc;
	FILE *fp;
	char *gpi, *gpd;
	OM_uint32 major_status, minor_status;

	struct gsi_plugin_data *data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);

	if (lifetime < 120) {	/* our credential will expire in two minutes, so let's renew it */

		/* get the Globus Toolkit path */
		globus_location = strdup(getenv("GLOBUS_LOCATION"));

		if (!globus_location)
			return 1;

		/* setup the grid-proxy-init command */
		gpi = (char *) calloc(strlen(globus_location) + strlen(init) + strlen(grid_proxy_init_args) + 1, sizeof(char));
		if (!gpi) {
			free(globus_location);
			return 1;
		}

		strncat(gpi, globus_location, strlen(globus_location));
		strncat(gpi, init, strlen(init));
		strncat(gpi, grid_proxy_init_args, strlen(grid_proxy_init_args));

		/* setup the grid-proxy-destroy command */
		gpd = (char *) calloc(strlen(globus_location) + strlen(destroy) + 1, sizeof(char));
		if (!gpd) {
			free(globus_location);
			free(gpi);
			return 1;
		}
		strncat(gpd, globus_location, strlen(globus_location));
		strncat(gpd, destroy, strlen(destroy));

		/* destroy the current, expired proxy */
		fp = popen(gpd, "r+");
		if (!fp) {
			free(globus_location);
			free(gpi);
			free(gpd);
			return 1;
		}
		(void) pclose(fp);


		/* release our previous, expired  credential */
		if (data->credential != GSS_C_NO_CREDENTIAL) {
			major_status = gss_release_cred(&minor_status, &data->credential);
			if (major_status != GSS_S_COMPLETE) {
				fprintf(stderr, "%s:  gss_release_cred() failed\n", GSI_PLUGIN_ID);
			}
			data->credential = GSS_C_NO_CREDENTIAL;
		}


		/* create a new proxy, enter the password on behalf of the user */
		fp = popen(gpi, "r+");
		if (!fp) {
			free(globus_location);
			free(gpi);
			return 1;
		}
		fwrite(proxy_pwd, sizeof(proxy_pwd), 1, fp);
		(void) pclose(fp);

		free(globus_location);
		free(gpi);
		free(gpd);

		/* now acquire the new credential */
		rc = gsi_acquire_credential(soap);
		return rc;

	}

	/* end if */
	/* if we arrive here, then our credential is still valid for more than two minutes */
	return 0;
}

/*
 * gsi_authorization_callback
 *
 * checks the received distinguished name against an access control list
 * stored in the file called authorized_dn. If the distinguished name
 * received belongs
 * to the access control list then the client can safely access
 * the service
 *
 */

int gsi_authorization_callback(struct soap *soap, char *distinguished_name)
{
	char buf[256] = { '\0' };
	char *auth;
	char *auth_file;
	FILE *fd;

	struct gsi_plugin_data *data;

	data = (struct gsi_plugin_data *) soap_lookup_plugin(soap, GSI_PLUGIN_ID);

	auth = globus_libc_getenv("AUTHORIZATION_FILE");
	if (auth != NULL) {
		auth_file = strdup(auth);
	} else {
		auth_file = strdup(AUTHORIZATION_FILE);
	}

	fd = fopen(auth_file, "r");

	if (!fd) {

		globus_libc_printf("Can not read file: %s\n", auth_file);
		return 1;
	}
	while (fgets(buf, 512, fd) != NULL) {
		buf[strlen(buf) - 1] = '\0';
		if (!strcmp(distinguished_name, buf)) {

			if (auth)
				free(auth);
			if (auth_file)
				free(auth_file);

			fclose(fd);

			return 0;
		}
	}
	if (auth)
		free(auth);
	if (auth_file)
		free(auth_file);
	fclose(fd);

	globus_libc_printf("Sorry, service %s is not authorized\n", distinguished_name);
	return 1;
}

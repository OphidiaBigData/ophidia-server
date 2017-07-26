/*
    Ophidia Server
    Copyright (C) 2012-2017 CMCC Foundation

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

#ifndef OPH_GATHER_H
#define OPH_GATHER_H

#include "soapStub.h"
#include "debug.h"
#include "oph_server_error.h"

#define UNUSED(x) {(void)(x);}

#define OPH_SERVER_LOCATION_STR "OPH_SERVER_LOCATION"

#define OPH_VERSION	"Ophidia Server, version " PACKAGE_VERSION "\nCopyright (C) 2012-2017 CMCC Foundation - www.cmcc.it\n"
#define OPH_DISCLAIMER	"This program comes with ABSOLUTELY NO WARRANTY; for details type `oph_server -x'.\nThis is free software, and you are welcome to redistribute it\nunder certain conditions; type `oph_server -z' for details.\n"
#define OPH_DISCLAIMER2	"This program comes with ABSOLUTELY NO WARRANTY; for details type `oph_client -x'.\nThis is free software, and you are welcome to redistribute it\nunder certain conditions; type `oph_client -z' for details.\n"
#define OPH_WARRANTY	"\nTHERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\n"
#include "oph_license.h"

// Configuration parameters
#define OPH_SERVER_CONF_PROTOCOL "PROTOCOL"
#define OPH_SERVER_CONF_HOST "HOST"
#define OPH_SERVER_CONF_PORT "PORT"
#define OPH_SERVER_CONF_TIMEOUT "TIMEOUT"
#define OPH_SERVER_CONF_INACTIVITY_TIMEOUT "INACTIVITY_TIMEOUT"
#define OPH_SERVER_CONF_WORKFLOW_TIMEOUT "WORKFLOW_TIMEOUT"
#define OPH_SERVER_CONF_LOGFILE "LOGFILE"
#define OPH_SERVER_CONF_CERT "CERT"
#define OPH_SERVER_CONF_CA "CA"
#define OPH_SERVER_CONF_CERT_PASSWORD "CERT_PASSWORD"
#define OPH_SERVER_CONF_RMANAGER_CONF_FILE "RMANAGER_CONF_FILE"
#define OPH_SERVER_CONF_AUTHZ_DIR "AUTHZ_DIR"
#define OPH_SERVER_CONF_TXT_DIR "TXT_DIR"
#define OPH_SERVER_CONF_WEB_SERVER "WEB_SERVER"
#define OPH_SERVER_CONF_WEB_SERVER_LOCATION "WEB_SERVER_LOCATION"
#define OPH_SERVER_CONF_OPERATOR_CLIENT "OPERATOR_CLIENT"
#define OPH_SERVER_CONF_IP_TARGET_HOST "IP_TARGET_HOST"
#define OPH_SERVER_CONF_SUBM_USER "SUBM_USER"
#define OPH_SERVER_CONF_SUBM_USER_PUBLK "SUBM_USER_PUBLK"
#define OPH_SERVER_CONF_SUBM_USER_PRIVK "SUBM_USER_PRIVK"
#define OPH_SERVER_CONF_XML_URL "OPH_XML_URL"
#define OPH_SERVER_CONF_XML_DIR "OPH_XML_DIR"
#define OPH_SERVER_CONF_ADMIN "ADMINISTRATOR"
#define OPH_SERVER_CONF_NOTIFIER "NOTIFIER"
#define OPH_SERVER_CONF_SERVER_FARM_SIZE "SERVER_FARM_SIZE"
#define OPH_SERVER_CONF_QUEUE_SIZE "QUEUE_SIZE"
#define OPH_SERVER_CONF_AUTO_RETRY "AUTO_RETRY"
#define OPH_SERVER_CONF_POLL_TIME "POLL_TIME"
#define OPH_SERVER_CONF_BASE_SRC_PATH "BASE_SRC_PATH"
#define OPH_SERVER_CONF_BASE_BACKOFF "BASE_BACKOFF"
#ifdef OPH_OPENID_ENDPOINT
#define OPH_SERVER_CONF_OPENID_ENDPOINT "OPENID_ENDPOINT"
#define OPH_SERVER_CONF_OPENID_CLIENT_ID "OPENID_CLIENT_ID"
#define OPH_SERVER_CONF_OPENID_CLIENT_SECRET "OPENID_CLIENT_SECRET"
#define OPH_SERVER_CONF_OPENID_TOKEN_TIMEOUT "OPENID_TOKEN_TIMEOUT"
#endif

// Security
#define OPH_SERVER_CERT "%s/etc/cert/myserver.pem"
#define OPH_SERVER_CA "%s/etc/cert/cacert.pem"
#define OPH_SERVER_PASSWORD "abcd"
#define OPH_SERVER_AUTHZ "%s/authz"
#define OPH_SERVER_WSDL "%s/etc/oph.wsdl"

// Server info
#ifdef INTERFACE_TYPE_IS_GSI
#define OPH_DEFAULT_PROTOCOL "httpg"
#else
#ifdef WITH_OPENSSL
#define OPH_DEFAULT_PROTOCOL "https"
#else
#define OPH_DEFAULT_PROTOCOL "http"
#endif
#endif
#define OPH_DEFAULT_HOST "localhost"
#define OPH_DEFAULT_PORT "11732"
#define OPH_CONFIGURATION_FILE "%s/etc/server.conf"
#define OPH_SERVER_TIMEOUT 3600	// sec
#define OPH_SERVER_INACTIVITY_TIMEOUT 31536000	// sec
#define OPH_SERVER_WORKFLOW_TIMEOUT 2592000	// sec
#define OPH_USER_ADMIN "admin"
#define OPH_USER_NOTIFIER "framework"
#define OPH_SERVER_POLL_TIME 0	// sec
#define OPH_SERVER_POLL_ITEMS 128	// tasks
#define OPH_BASE_SRC_PATH ""
#define OPH_SERVER_DEV_NULL "/dev/null"

// RMS info
#define OPH_RMANAGER_CONF_FILE "%s/etc/rmanager.conf"
#define OPH_OPERATOR_CLIENT "/usr/local/ophidia/oph-cluster/oph-analytics-framework/bin/oph_analytics_framework"
#define OPH_IP_TARGET_HOST "127.0.0.1"
#define OPH_SUBM_USER "ophidia"
#define OPH_SUBM_USER_PUBLK "/usr/local/ophidia/.ssh/id_dsa.pub"
#define OPH_SUBM_USER_PRIVK "/usr/local/ophidia/.ssh/id_dsa"

// Web server
#define OPH_WEB_SERVER "http://localhost"
#define OPH_WEB_SERVER_LOCATION "/var/www/html/ophidia"

// Session
#define OPH_SESSION_WORKFLOW_DELIMITER "?"
#define OPH_SESSION_MARKER_DELIMITER "#"
#define OPH_SESSION_BASE_TEMPLATE "%s/sessions"
#define OPH_SESSION_FOLDER_TEMPLATE OPH_SESSION_BASE_TEMPLATE"/%s"
#define OPH_SESSION_JSON_FOLDER_TEMPLATE OPH_SESSION_FOLDER_TEMPLATE"/json"
#define OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE OPH_SESSION_JSON_FOLDER_TEMPLATE"/request"
#define OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE OPH_SESSION_JSON_FOLDER_TEMPLATE"/response"
#define OPH_SESSION_EXPORT_FOLDER_TEMPLATE OPH_SESSION_FOLDER_TEMPLATE"/export"
#define OPH_SESSION_MISCELLANEA_FOLDER_TEMPLATE OPH_SESSION_EXPORT_FOLDER_TEMPLATE"/misc"
#define OPH_SESSIONID_TEMPLATE OPH_SESSION_BASE_TEMPLATE"/%s/experiment"

// Other server info
#define OPH_DBMS_CONF_FILE "%s/etc/ophidiadb.conf"
#define OPH_JSON_REQUEST_FILENAME OPH_SESSION_JSON_REQUEST_FOLDER_TEMPLATE"/%s.json"
#define OPH_JSON_RESPONSE_FILENAME OPH_SESSION_JSON_RESPONSE_FOLDER_TEMPLATE"/%s.json"
#define OPH_TXT_FILENAME "%s/%s_%s.txt"
#define OPH_TXT_LOCATION "%s/log"

// Other consts
#define OPH_MAX_PROGRAM_SIZE 1048576
#define OPH_MAX_STRING_SIZE 4096
#define OPH_SHORT_STRING_SIZE 128

// Internal XML
#define OPH_SERVER_XML_PATH "%s/etc/xml"
#define OPH_SERVER_XML_FILE "%s/etc/xml/%s"
#define OPH_SERVER_DTD_SCHEMA "%s/etc/dtd/ophidiaoperator.dtd"
// External XML
#define OPH_SERVER_XML_EXT_PATH "/usr/local/ophidia/oph-cluster/oph-analytics-framework/etc/operators_xml"
#define OPH_SERVER_XML_EXT_FILE "%s/%s"

// Job status
#define OPH_ODB_STATUS_UNKNOWN_STR "OPH_STATUS_UNKNOWN"
#define OPH_ODB_STATUS_PENDING_STR "OPH_STATUS_PENDING"
#define OPH_ODB_STATUS_WAIT_STR "OPH_STATUS_WAITING"
#define OPH_ODB_STATUS_RUNNING_STR "OPH_STATUS_RUNNING"
#define OPH_ODB_STATUS_START_STR "OPH_STATUS_RUNNING"
#define OPH_ODB_STATUS_SET_ENV_STR "OPH_STATUS_SET_ENV"
#define OPH_ODB_STATUS_INIT_STR "OPH_STATUS_INIT"
#define OPH_ODB_STATUS_DISTRIBUTE_STR "OPH_STATUS_DISTRIBUTE"
#define OPH_ODB_STATUS_EXECUTE_STR "OPH_STATUS_EXECUTE"
#define OPH_ODB_STATUS_REDUCE_STR "OPH_STATUS_REDUCE"
#define OPH_ODB_STATUS_DESTROY_STR "OPH_STATUS_DESTROY"
#define OPH_ODB_STATUS_UNSET_ENV_STR "OPH_STATUS_UNSET_ENV"
#define OPH_ODB_STATUS_COMPLETED_STR "OPH_STATUS_COMPLETED"
#define OPH_ODB_STATUS_ERROR_STR "OPH_STATUS_ERROR"
#define OPH_ODB_STATUS_PENDING_ERROR_STR "OPH_STATUS_PENDING_ERROR"
#define OPH_ODB_STATUS_RUNNING_ERROR_STR "OPH_STATUS_RUNNING_ERROR"
#define OPH_ODB_STATUS_START_ERROR_STR "OPH_STATUS_START_ERROR"
#define OPH_ODB_STATUS_SET_ENV_ERROR_STR "OPH_STATUS_SET_ENV_ERROR"
#define OPH_ODB_STATUS_INIT_ERROR_STR "OPH_STATUS_INIT_ERROR"
#define OPH_ODB_STATUS_DISTRIBUTE_ERROR_STR "OPH_STATUS_DISTRIBUTE_ERROR"
#define OPH_ODB_STATUS_EXECUTE_ERROR_STR "OPH_STATUS_EXECUTE_ERROR"
#define OPH_ODB_STATUS_REDUCE_ERROR_STR "OPH_STATUS_REDUCE_ERROR"
#define OPH_ODB_STATUS_DESTROY_ERROR_STR "OPH_STATUS_DESTROY_ERROR"
#define OPH_ODB_STATUS_UNSET_ENV_ERROR_STR "OPH_STATUS_UNSET_ENV_ERROR"
#define OPH_ODB_STATUS_SKIPPED_STR "OPH_STATUS_SKIPPED"
#define OPH_ODB_STATUS_ABORTED_STR "OPH_STATUS_ABORTED"
#define OPH_ODB_STATUS_UNSELECTED_STR "OPH_STATUS_UNSELECTED"
#define OPH_ODB_STATUS_EXPIRED_STR "OPH_STATUS_EXPIRED"
#define OPH_ODB_STATUS_CLOSED_STR "OPH_STATUS_CLOSED"

// Client configuration parameters
#define OPH_CLIENT_XML_URL "http://localhost/ophidia/operators_xml"

enum oph__oph_odb_job_status { OPH_ODB_STATUS_UNKNOWN, OPH_ODB_STATUS_PENDING, OPH_ODB_STATUS_WAIT, OPH_ODB_STATUS_RUNNING, OPH_ODB_STATUS_START, OPH_ODB_STATUS_SET_ENV, OPH_ODB_STATUS_INIT,
	OPH_ODB_STATUS_DISTRIBUTE, OPH_ODB_STATUS_EXECUTE, OPH_ODB_STATUS_REDUCE, OPH_ODB_STATUS_DESTROY, OPH_ODB_STATUS_UNSET_ENV, OPH_ODB_STATUS_COMPLETED, OPH_ODB_STATUS_ERROR,
	OPH_ODB_STATUS_PENDING_ERROR, OPH_ODB_STATUS_RUNNING_ERROR, OPH_ODB_STATUS_START_ERROR, OPH_ODB_STATUS_SET_ENV_ERROR, OPH_ODB_STATUS_INIT_ERROR, OPH_ODB_STATUS_DISTRIBUTE_ERROR,
	OPH_ODB_STATUS_EXECUTE_ERROR, OPH_ODB_STATUS_REDUCE_ERROR, OPH_ODB_STATUS_DESTROY_ERROR, OPH_ODB_STATUS_UNSET_ENV_ERROR, OPH_ODB_STATUS_SKIPPED, OPH_ODB_STATUS_ABORTED,
	OPH_ODB_STATUS_UNSELECTED, OPH_ODB_STATUS_EXPIRED, OPH_ODB_STATUS_CLOSED
};

#endif				/* OPH_GATHER_H */

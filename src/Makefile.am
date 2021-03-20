#
#    Ophidia Server
#    Copyright (C) 2012-2021 CMCC Foundation
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

bin_PROGRAMS=oph_client oph_server oph_manage_user
bindir=${prefix}/bin

ADDITIONAL_CFLAGS = -I$(INTERFACE_TYPE) $(LIBSSL_INCLUDE) -DOPH_SERVER_LOCATION=\"${prefix}\" $(OPT) -DCOMMAND_TO_JSON -DLEVEL1
ADDITIONAL_LIBS = -lm -lpthread

if SSH_SUPPORT
ADDITIONAL_CFLAGS += -DSSH_SUPPORT
LIBSSH2_CFLAGS = ${SSH2_CFLAGS}
LIBSSH2_LIBS = ${SSH2_LIBS}
else
LIBSSH2_CFLAGS =
LIBSSH2_LIBS =
endif

if OPENID_SUPPORT
ADDITIONAL_CFLAGS += -DOPH_OPENID_SUPPORT -DBLACK_LIST_FILE=\"@BLACK_LIST_FILE@\" -DAUTHORIZED_VO_FILE=\"@AUTHORIZED_VO_FILE@\"
OPENID_CFLAGS = ${LIBCURL_INCLUDE} $(JANSSON_CFLAGS) $(CJOSE_CFLAGS)
OPENID_LDFLAGS = -Wl,-rpath -Wl,$(JANSSON_LIBDIR)
OPENID_LIBS = ${LIBCURL_LIB} $(JANSSON_LIBS) $(CJOSE_LIBS)
else
OPENID_CFLAGS =
OPENID_LDFLAGS =
OPENID_LIBS =
endif

if AAA_SUPPORT
ADDITIONAL_CFLAGS += -DOPH_AAA_SUPPORT -DBLACK_LIST_FILE=\"@BLACK_LIST_FILE@\" -DAUTHORIZED_VO_FILE=\"@AUTHORIZED_VO_FILE@\"
AAA_CFLAGS = ${LIBCURL_INCLUDE} $(JANSSON_CFLAGS)
AAA_LDFLAGS = -Wl,-rpath -Wl,$(JANSSON_LIBDIR)
AAA_LIBS = ${LIBCURL_LIB} $(JANSSON_LIBS)
else
AAA_CFLAGS =
AAA_LDFLAGS =
AAA_LIBS =
endif

if DB_SUPPORT
ADDITIONAL_CFLAGS += -DOPH_DB_SUPPORT
else
ADDITIONAL_CFLAGS += $(SQLITE_INCLUDE)
ADDITIONAL_LIBS += $(SQLITE_LIB)
endif

if INTERFACE_TYPE_IS_SSL
ADDITIONAL_CFLAGS += -DWITH_OPENSSL -DHAVE_OPENSSL_SSL_H -DINTERFACE_TYPE_IS_SSL
ADDITIONAL_LIBS += $(LIBSSL_LIB)
DEFINE_THREADS = -D_REENTRANT=$(REENTRANT)
endif

if INTERFACE_TYPE_IS_GSI

ADDITIONAL_CFLAGS += -DINTERFACE_TYPE_IS_GSI
DEFINE = -DPLUGIN_DEFAULT_PORT=$(PLUGIN_DEFAULT_PORT) \
	-DPLUGIN_DEFAULT_HOSTNAME=\"$(PLUGIN_DEFAULT_HOSTNAME)\" \
	-DAUTHORIZATION_FILE=\"$(AUTHORIZATION_FILE)\" \
	-DBLACK_LIST_FILE=\"$(BLACK_LIST_FILE)\" \
	-DAUTHORIZED_VO_FILE=\"$(AUTHORIZED_VO_FILE)\" \
	-DGSI_PLUGIN_DEBUG=1
DEFINE_THREADS = $(DEFINE) -D_REENTRANT=$(REENTRANT) -DGSI_PLUGIN_THREADS=$(GSI_PLUGIN_THREADS)

if VOMS
GLOBUS_LIBS = -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_proxy_ssl -lglobus_openssl_error -lssl -lcrypto -lglobus_common
GLOBUS_LIBS_THREADED = -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_proxy_ssl -lglobus_openssl_error -lssl -lcrypto -lglobus_common -lpthread
GLOBUS_GRAM_LIBS = -lglobus_gram_client -lglobus_gram_protocol -lglobus_io -lglobus_gss_assist -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_proxy_ssl -lglobus_openssl_error -lssl -lcrypto -lglobus_common
GLOBUS_GRAM_LIBS_THREADED = -lglobus_gram_client -lglobus_gram_protocol -lglobus_io -lglobus_gss_assist -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_proxy_ssl -lglobus_openssl_error -lssl -lcrypto -lglobus_common -lpthread
AM_CFLAGS = $(OPT) -D$(PLATFORM) -D$(VOMS_DEFINE) -I../include -I$(VOMS_INCLUDE) -Wall
MYCFLAGS = $(AM_CFLAGS) -I$(GLOBUS_INCLUDE) $(DEFINE)
MYCFLAGS_THREADS = $(AM_CFLAGS) -I$(GLOBUS_INCLUDE) $(DEFINE_THREADS)
VOMS_LINK = -lvomsapi
VOMS_LINK_THREADED = -lvomsapi
MYLDFLAGS  = -L. -lgsigsoap -L$(VOMS_LIBS) $(VOMS_LINK) -L$(GLOBUS_LIB) $(GLOBUS_LIBS)
MYLDFLAGS_THREADS  = -L. -lgsigsoapthreads -L$(VOMS_LIBS) $(VOMS_LINK_THREADED) -L$(GLOBUS_LIB) $(GLOBUS_LIBS_THREADED)
MYGRAMLDFLAGS  = -L. -lgsigsoap -L$(VOMS_LIBS) $(VOMS_LINK) -L$(GLOBUS_LIB) $(GLOBUS_GRAM_LIBS)
MYGRAMLDFLAGS_THREADS  = -L. -lgsigsoapthreads -L$(VOMS_LIBS) $(VOMS_LINK_THREADED) -L$(GLOBUS_LIB) $(GLOBUS_GRAM_LIBS_THREADED)
else
GLOBUS_LIBS = -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_openssl_error -lglobus_proxy_ssl -lglobus_common -lssl -lcrypto -lltdl
GLOBUS_LIBS_THREADED = -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_openssl_error -lglobus_proxy_ssl -lglobus_common -lssl -lcrypto -lltdl -lpthread
GLOBUS_GRAM_LIBS = -lglobus_gram_client -lglobus_gram_protocol -lglobus_io -lglobus_xio -lgssapi_error -lglobus_gss_assist -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_openssl_error -lglobus_proxy_ssl -lglobus_common -lssl -lcrypto -lltdl -lm
GLOBUS_GRAM_LIBS_THREADED = -lglobus_gram_client -lglobus_gram_protocol -lglobus_io -lglobus_xio -lgssapi_error -lglobus_gss_assist -lglobus_gssapi_gsi -lglobus_gsi_proxy_core -lglobus_gsi_credential -lglobus_gsi_callback -lglobus_oldgaa -lglobus_gsi_sysconfig -lglobus_gsi_cert_utils -lglobus_openssl -lglobus_openssl_error -lglobus_proxy_ssl -lglobus_common -lssl -lcrypto -lltdl -lm -lpthread
AM_CFLAGS = $(OPT) -D$(PLATFORM) -I../include -Wall
MYCFLAGS = $(AM_CFLAGS) -I$(GLOBUS_INCLUDE) $(DEFINE)
MYCFLAGS_THREADS = $(AM_CFLAGS) -I$(GLOBUS_INCLUDE) $(DEFINE_THREADS)
MYLDFLAGS  = -L. -lgsigsoap -L$(GLOBUS_LIB) $(GLOBUS_LIBS)
MYLDFLAGS_THREADS  = -L. -lgsigsoapthreads -L$(GLOBUS_LIB) $(GLOBUS_LIBS_THREADED)
MYGRAMLDFLAGS  = -L. -lgsigsoap -L$(GLOBUS_LIB) $(GLOBUS_GRAM_LIBS)
MYGRAMLDFLAGS_THREADS  = -L. -lgsigsoapthreads -L$(GLOBUS_LIB) $(GLOBUS_GRAM_LIBS_THREADED)
endif
GLOBUS_BASIC = -L. -lglobus_common

else

AM_CFLAGS = $(OPT)
MYCFLAGS =
MYCFLAGS_THREADS =
MYLDFLAGS =
MYLDFLAGS_THREADS =
GLOBUS_BASIC =

endif

if OPH_WEB_ACCESS
ADDITIONAL_CFLAGS += -DOPH_WEB_ACCESS
endif

if MATHEVAL_SUPPORT
ADDITIONAL_CFLAGS += -DMATHEVAL_SUPPORT $(MATHEVAL_CFLAGS)
ADDITIONAL_LIBS += $(MATHEVAL_LIBS)
endif

LIBRARY =

LIBRARY += libhashtbl.la
libhashtbl_la_SOURCES = hashtbl.c
libhashtbl_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libhashtbl_la_LDFLAGS = -shared
libhashtbl_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_json.la
liboph_json_la_SOURCES = oph_json/oph_json_common.c oph_json/oph_json_graph.c oph_json/oph_json_grid.c  oph_json/oph_json_multigrid.c oph_json/oph_json_text.c oph_json/oph_json_tree.c
liboph_json_la_CFLAGS= -prefer-pic -I. -Ioph_json $(JANSSON_CFLAGS) ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_json_la_LDFLAGS = -shared -Wl,-rpath -Wl,$(JANSSON_LIBDIR)
liboph_json_la_LIBADD = $(ADDITIONAL_LIBS) $(JANSSON_LIBS)

LIBRARY += liboph_workflow.la
liboph_workflow_la_SOURCES = oph_workflow/oph_workflow_parsing.c oph_workflow/oph_workflow_setup.c oph_workflow/oph_workflow_structs.c oph_workflow/oph_workflow_utils.c
liboph_workflow_la_CFLAGS= -prefer-pic -I. -Ioph_workflow $(JANSSON_CFLAGS) ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_workflow_la_LDFLAGS = -shared -Wl,-rpath -Wl,$(JANSSON_LIBDIR)
liboph_workflow_la_LIBADD = $(ADDITIONAL_LIBS) $(JANSSON_LIBS) -L. -lhashtbl

LIBRARY += libdebug.la
libdebug_la_SOURCES = debug.c
libdebug_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libdebug_la_LDFLAGS = -shared
libdebug_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += libsoapC.la
libsoapC_la_SOURCES = soapC.c
libsoapC_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libsoapC_la_LDFLAGS = -shared
libsoapC_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += libstdsoap2.la
libstdsoap2_la_SOURCES = stdsoap2.c
libstdsoap2_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libstdsoap2_la_LDFLAGS = -shared
libstdsoap2_la_LIBADD = $(ADDITIONAL_LIBS) -L. -lsoapC

LIBRARY += libthreads.la
libthreads_la_SOURCES = threads.c
libthreads_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libthreads_la_LDFLAGS = -shared
libthreads_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += libsoapClient.la
libsoapClient_la_SOURCES = soapClient.c
libsoapClient_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libsoapClient_la_LDFLAGS = -shared
libsoapClient_la_LIBADD = $(ADDITIONAL_LIBS) -L. -lstdsoap2

LIBRARY += libsoapServer.la
libsoapServer_la_SOURCES = soapServer.c
libsoapServer_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libsoapServer_la_LDFLAGS = -shared
libsoapServer_la_LIBADD = $(ADDITIONAL_LIBS) -L. -lstdsoap2

LIBRARY += libutils.la
libutils_la_SOURCES = oph_utils.c
libutils_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
libutils_la_LDFLAGS = -shared
libutils_la_LIBADD = $(ADDITIONAL_LIBS) -L. -lstdsoap2

LIBRARY += liboph_service_info.la
liboph_service_info_la_SOURCES = oph_service_info.c
liboph_service_info_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_service_info_la_LDFLAGS = -shared
liboph_service_info_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_parser.la
liboph_parser_la_SOURCES = oph_parser.c
liboph_parser_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_parser_la_LDFLAGS = -shared
liboph_parser_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_ophidiadb.la
liboph_ophidiadb_la_SOURCES = oph_ophidiadb.c
liboph_ophidiadb_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS)
liboph_ophidiadb_la_LDFLAGS = -shared
liboph_ophidiadb_la_LIBADD = $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS}

LIBRARY += liboph_auth.la
liboph_auth_la_SOURCES = oph_auth.c
liboph_auth_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) $(OPENID_CFLAGS) $(AAA_CFLAGS)
liboph_auth_la_LDFLAGS = -shared $(OPENID_LDFLAGS) $(AAA_LDFLAGS)
liboph_auth_la_LIBADD = $(ADDITIONAL_LIBS) $(OPENID_LIBS) $(AAA_LIBS) -L. -loph_ophidiadb -loph_parser -loph_service_info -lhashtbl

LIBRARY += liboph_ssh_submit.la
liboph_ssh_submit_la_SOURCES = oph_ssh_submit.c
liboph_ssh_submit_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) ${LIBSSH2_CFLAGS}
liboph_ssh_submit_la_LDFLAGS = -shared
liboph_ssh_submit_la_LIBADD = $(ADDITIONAL_LIBS) ${LIBSSH2_LIBS}

LIBRARY += liboph_rmanager.la
liboph_rmanager_la_SOURCES = oph_rmanager.c
liboph_rmanager_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) -loph_service_info -Ioph_workflow
liboph_rmanager_la_LDFLAGS = -shared
liboph_rmanager_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_ssh_submit -lutils

LIBRARY += liboph_subset_library.la
liboph_subset_library_la_SOURCES = oph_subset_library.c
liboph_subset_library_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_subset_library_la_LDFLAGS = -shared
liboph_subset_library_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_session_report.la
liboph_session_report_la_SOURCES = oph_session_report.c
liboph_session_report_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_session_report_la_LDFLAGS = -shared
liboph_session_report_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_job_list.la
liboph_job_list_la_SOURCES = oph_job_list.c
liboph_job_list_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) -Ioph_workflow
liboph_job_list_la_LDFLAGS = -shared
liboph_job_list_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_workflow

LIBRARY += liboph_trash.la
liboph_trash_la_SOURCES = oph_trash.c
liboph_trash_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS)
liboph_trash_la_LDFLAGS = -shared
liboph_trash_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_plugin.la
liboph_plugin_la_SOURCES = oph_plugin.c
liboph_plugin_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) -Ioph_workflow
liboph_plugin_la_LDFLAGS = -shared
liboph_plugin_la_LIBADD = $(ADDITIONAL_LIBS)

LIBRARY += liboph_memory_job.la
liboph_memory_job_la_SOURCES = oph_memory_job.c
liboph_memory_job_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) -Ioph_workflow
liboph_memory_job_la_LDFLAGS = -shared
liboph_memory_job_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_job_list

LIBRARY += liboph_ophidiadb_fs_library.la
liboph_ophidiadb_fs_library_la_SOURCES = oph_ophidiadb_fs_library.c
liboph_ophidiadb_fs_library_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS)
liboph_ophidiadb_fs_library_la_LDFLAGS = -shared
liboph_ophidiadb_fs_library_la_LIBADD = $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS} -L. -loph_ophidiadb

LIBRARY += liboph_task_parser_library.la
liboph_task_parser_library_la_SOURCES = oph_task_parser_library.c
liboph_task_parser_library_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) ${XML_CFLAGS}
liboph_task_parser_library_la_LDFLAGS = -shared
liboph_task_parser_library_la_LIBADD = $(ADDITIONAL_LIBS) ${XML_LIBS}

LIBRARY += liboph_filters.la
liboph_filters_la_SOURCES = oph_filters.c
liboph_filters_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS)
liboph_filters_la_LDFLAGS = -shared
liboph_filters_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_task_parser_library -loph_ophidiadb_fs_library -loph_subset_library

LIBRARY += liboph_massive_operations.la
liboph_massive_operations_la_SOURCES = oph_massive_operations.c
liboph_massive_operations_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) -Ioph_workflow
liboph_massive_operations_la_LDFLAGS = -shared
liboph_massive_operations_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_filters -loph_rmanager

LIBRARY += liboph_odb_job.la
liboph_odb_job_la_SOURCES = oph_odb_job.c
liboph_odb_job_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS)
liboph_odb_job_la_LDFLAGS = -shared
liboph_odb_job_la_LIBADD = $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS}

LIBRARY += liboph_workflow_engine.la
liboph_workflow_engine_la_SOURCES = oph_workflow_engine.c
liboph_workflow_engine_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) ${LIBCURL_INCLUDE} -Ioph_workflow
liboph_workflow_engine_la_LDFLAGS = -shared ${LIBCURL_LIB}
liboph_workflow_engine_la_LIBADD = $(ADDITIONAL_LIBS) -L. -lutils -loph_service_info -loph_auth -loph_massive_operations -loph_json -loph_memory_job -loph_odb_job -loph_session_report -loph_trash

LIBRARY += liboph_execute_main.la
liboph_execute_main_la_SOURCES = oph_execute_main.c
liboph_execute_main_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) -Ioph_workflow $(MYCFLAGS_THREADS)
liboph_execute_main_la_LDFLAGS = -shared
liboph_execute_main_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_workflow_engine

LIBRARY += liboph_notify.la
liboph_notify_la_SOURCES = oph_notify.c
liboph_notify_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) $(CURL_CFLAGS) -Ioph_workflow $(MYCFLAGS_THREADS)
liboph_notify_la_LDFLAGS = -shared
liboph_notify_la_LIBADD = $(ADDITIONAL_LIBS) ${CURL_LIBS} -L. -loph_workflow_engine

LIBRARY += liboph_flow_control_operators.la
liboph_flow_control_operators_la_SOURCES = oph_flow_control_operators.c
liboph_flow_control_operators_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) ${LIBCURL_INCLUDE} -Ioph_workflow
liboph_flow_control_operators_la_LDFLAGS = -shared ${LIBCURL_LIB}
liboph_flow_control_operators_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_service_info -loph_workflow_engine

LIBRARY += liboph_management_operators.la
liboph_management_operators_la_SOURCES = oph_management_operators.c
liboph_management_operators_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) -Ioph_workflow
liboph_management_operators_la_LDFLAGS = -shared
liboph_management_operators_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_workflow_engine

LIBRARY += liboph_known_operators.la
liboph_known_operators_la_SOURCES = oph_known_operators.c
liboph_known_operators_la_CFLAGS = -prefer-pic -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) -Ioph_workflow
liboph_known_operators_la_LDFLAGS = -shared
liboph_known_operators_la_LIBADD = $(ADDITIONAL_LIBS) -L. -loph_flow_control_operators -loph_management_operators

if INTERFACE_TYPE_IS_GSI
LIBRARY += libgsigsoap.la libgsigsoapthreads.la
libgsigsoap_la_SOURCES = $(INTERFACE_TYPE)/gsi.c
libgsigsoap_la_CFLAGS = $(MYCFLAGS)
libgsigsoap_la_LDFLAGS = -shared
libgsigsoapthreads_la_SOURCES = $(INTERFACE_TYPE)/gsi.c
libgsigsoapthreads_la_CFLAGS = $(MYCFLAGS_THREADS)
libgsigsoapthreads_la_LDFLAGS = -shared
endif

lib_LTLIBRARIES = $(LIBRARY)

oph_client_SOURCES= $(INTERFACE_TYPE)/oph_client.c
oph_client_CFLAGS= $(OPT) -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYCFLAGS)
oph_client_LDFLAGS= $(MYLDFLAGS)
oph_client_LDADD= $(ADDITIONAL_LIBS) -L. -lsoapClient -lstdsoap2 -ldebug

oph_server_SOURCES= $(INTERFACE_TYPE)/oph_server.c
oph_server_CFLAGS= $(OPT) -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) -Ioph_workflow $(MYSQL_CFLAGS) $(MYCFLAGS_THREADS)
oph_server_LDFLAGS= $(MYLDFLAGS_THREADS)
oph_server_LDADD= $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS} -L. -lsoapServer -lstdsoap2 -lutils -loph_ophidiadb -loph_auth -loph_task_parser_library -lhashtbl -loph_service_info -loph_odb_job -ldebug -lthreads -loph_plugin -loph_rmanager -loph_notify -loph_known_operators -loph_execute_main -loph_job_list -loph_workflow_engine

oph_manage_user_SOURCES= oph_manage_user.c
oph_manage_user_CFLAGS= $(OPT) -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) $(MYSQL_CFLAGS) $(MYCFLAGS)
oph_manage_user_LDFLAGS= $(GLOBUS_BASIC)
oph_manage_user_LDADD= $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS} -L. -ldebug -loph_parser -lhashtbl -loph_ophidiadb -loph_auth

clean-local:
	-rm -f *~ oph_json/*~ oph_workflow/*~ $(INTERFACE_TYPE)/*~

distclean-local:
	-rm -f *~ oph_json/*~ oph_workflow/*~ $(INTERFACE_TYPE)/*~

install-exec-hook:
	mkdir -p wsdl && \
	cd wsdl && \
	cat ../oph_types.h > oph_wsdl.h && \
	echo "//gsoap oph service location:      ${PLUGIN_DEFAULT_PROTOCOL}://${PLUGIN_DEFAULT_HOSTNAME}:${PLUGIN_DEFAULT_PORT}/" >> oph_wsdl.h && \
	cat ../oph_execute_main.h >> oph_wsdl.h && \
	$(SOAPCPP2_PROG) -c -x oph_wsdl.h && \
	cp -f *.wsdl $(OPH_WEB_SERVER_LOCATION)/ && \
	mv -f *.wsdl $(DESTDIR)$(sysconfdir)
	rm -rf wsdl

uninstall-local:
	rm $(DESTDIR)$(sysconfdir)/oph.wsdl

#
#    Ophidia Server
#    Copyright (C) 2012-2016 CMCC Foundation
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

TESTS=oph_server_test
check_PROGRAMS=oph_server_test

ADDITIONAL_CFLAGS = -I$(INTERFACE_TYPE) $(LIBSSL_INCLUDE) -DOPH_SERVER_LOCATION=\"${prefix}\" $(OPT) -DCOMMAND_TO_JSON -DLEVEL1
ADDITIONAL_LIBS = -lm -lpthread

if INTERFACE_TYPE_IS_SSL
ADDITIONAL_CFLAGS += -DWITH_OPENSSL -DHAVE_OPENSSL_SSL_H -DINTERFACE_TYPE_IS_SSL
ADDITIONAL_LIBS += $(LIBSSL_LIB)
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

lib_LTLIBRARIES =

oph_server_test_SOURCES= oph_server_test.c
oph_server_test_CFLAGS= $(OPT) -I. ${lib_CFLAGS} $(ADDITIONAL_CFLAGS) -I../src -I../src/oph_workflow $(MYSQL_CFLAGS) $(MYCFLAGS_THREADS)
oph_server_test_LDFLAGS= $(MYLDFLAGS_THREADS)
oph_server_test_LDADD= $(ADDITIONAL_LIBS) ${MYSQL_LDFLAGS} -L. -L../src -loph_json -loph_workflow -lsoapServer -lstdsoap2 -ldebug -lhashtbl -lthreads -loph_plugin -loph_job_list -loph_trash -loph_memory_job -loph_auth -loph_ophidiadb -loph_notify -loph_odb_job -loph_parser -loph_rmanager -loph_ssh_submit -loph_massive_operations -loph_task_parser_library -loph_filters -loph_subset_library -loph_ophidiadb_fs_library -loph_session_report -lutils -loph_known_operators -loph_execute_main

clean-local:
	-rm -f *~

distclean-local:
	-rm -f *~


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

AC_PREREQ([2.60])
AC_INIT([ophidia-server], [0.10.7], [ophidia-info@lists.cmcc.it])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_STDC
AM_PROG_CC_C_O

LT_INIT([disable-static])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h float.h inttypes.h limits.h locale.h memory.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h sys/timeb.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRTOD
AC_CHECK_FUNCS([ftime gethostbyname gettimeofday localtime_r memmove memset mkdir realpath select socket strcasecmp strchr strdup strerror strncasecmp strndup strrchr strstr strtol])

CFLAGS="-DWITH_DOM"
CPPFLAGS="-DWITH_DOM"
CXXFLAGS="-DWITH_DOM"

AX_CODE_COVERAGE

AX_LIB_MYSQL([5.6])
if test -n $HAVE_MYSQL; then
  AC_MSG_NOTICE([MySQL libraries available])
else
	AC_MSG_ERROR([MySQL libraries not found! Aborting configure!])
fi

optimization="no"
AC_ARG_ENABLE(optimization,
        [  --enable-optimization          turn on optimization flags],
        [optimization="yes"
        AC_MSG_NOTICE("Optimization activated")],
        [optimization="no"]
        )

matheval_support=no
MATHEVAL_CONFIG=
AC_ARG_WITH(matheval_path,
           [  --with-matheval-path=PATH  Set the MathEval library root dir],
           [
                matheval_path="$withval"
                                matheval_support=yes
                                MATHEVAL_CONFIG="${withval}/pkgconfig/libmatheval.pc"
           ],
           [
                        MATHEVAL_CONFIG="/usr/local/lib/pkgconfig/libmatheval.pc"
                        echo -n "checking for $MATHEVAL_CONFIG... "
                        if test -e "$MATHEVAL_CONFIG" ; then
                                matheval_support=yes
                        fi
                        echo "$matheval_support"
           ]
           )
if test "x${matheval_support}" = "xyes"; then
	MATHEVAL_CFLAGS="`pkg-config $MATHEVAL_CONFIG --cflags`"
	MATHEVAL_LIBS="`pkg-config $MATHEVAL_CONFIG --libs`"
        if test "x${MATHEVAL_LIBS}" != "x"; then
                AC_SUBST(MATHEVAL_CFLAGS)
                AC_SUBST(MATHEVAL_LIBS)
                AC_MSG_NOTICE("Matheval support enabled")
        else
                AC_MSG_WARN("Matheval support disabled")
                matheval_support=no
        fi
else
	AC_MSG_WARN("Matheval support disabled")
fi
AM_CONDITIONAL([MATHEVAL_SUPPORT], [test "x$matheval_support" = "xyes"])

AC_ARG_ENABLE(debug,
	   [  --enable-debug	Enable debug. (Disabled by default)],
	   [ debug="yes"],
           [ debug="no"]
	   )
if test "x$debug" = "xyes"; then
	AC_MSG_WARN("Debug activated")
	OPT="-g3 -Wall -Wextra -O0 -DLOCAL_FRAMEWORK -DUSE_MPI"
else
	OPT="-O2"
fi

AC_ARG_ENABLE(webaccess,
	   [  --enable-webaccess	Enable Web Access. (Disabled by default)],
	   [ webaccess="yes"],
           [ webaccess="no"]
	   )
if test "x$webaccess" = "xyes"; then
	AC_MSG_NOTICE("Web Access activated")
fi
AM_CONDITIONAL([OPH_WEB_ACCESS], [test "x${webaccess}" = "xyes"])

AC_ARG_WITH(interface_type,
	   [  --with-interface-type=TYPE 		Interface type: SSL],
	   [
		interface_type="$withval"
	   ],
	   [
		interface_type="ssl"
	   ])
if test "x${interface_type}" = "xssl"; then
INTERFACE_TYPE=$interface_type
elif test "x${interface_type}" = "xgsi"; then
INTERFACE_TYPE=$interface_type
else
AC_MSG_ERROR(Unsupported interface type)
fi
AC_SUBST(INTERFACE_TYPE)
AM_CONDITIONAL([INTERFACE_TYPE_IS_SSL], [test "x$interface_type" = "xssl"])
AM_CONDITIONAL([INTERFACE_TYPE_IS_GSI], [test "x$interface_type" = "xgsi"])

AC_ARG_WITH(globus-libs,
                                [  --with-globus-libs=GLOBUS_LIB_LOCATION   Set the Globus library location],
                                [GLOBUS_LIB="$withval"]
                                )
AC_SUBST(GLOBUS_LIB)
if test -n $GLOBUS_LIB; then
        AC_MSG_NOTICE([Globus library in: $GLOBUS_LIB])
fi

AC_ARG_WITH(globus-include,
                                [  --with-globus-include=GLOBUS_INCLUDE_LOCATION   Set the Globus header location],
                                [GLOBUS_INCLUDE="$withval"]
                                )
AC_SUBST(GLOBUS_INCLUDE)
if test -n $GLOBUS_INCLUDE; then
       AC_MSG_NOTICE([Globus includes: $GLOBUS_INCLUDE])
fi



gsi_plugin_threads_enable=0
GSI_PLUGIN_THREADS=$gsi_plugin_threads_enable
AC_SUBST(GSI_PLUGIN_THREADS)

#GLOBUS_INCLUDE_BASIC=$GLOBUS_LOCATION/include/$GLOBUS_FLAVOR
#AC_SUBST(GLOBUS_INCLUDE_BASIC)

#GLOBUS_INCLUDE_THREADS=$GLOBUS_LOCATION/include/$GLOBUS_FLAVOR_THREADS
#AC_SUBST(GLOBUS_INCLUDE_THREADS)




#Enable VOMS
voms_enable=0
AC_ARG_ENABLE(voms,
            [  --enable-voms  Enables support for VOMS on GLITE],
                     [voms_enable=1],
                     [voms_enable=0])
VOMS=$voms_enable
AC_SUBST(VOMS)

#Set VOMS libs path
AC_ARG_WITH(voms-libs,
            [  --with-voms-libs=VOMS_LIBS       Sets the VOMS libraries path],
                    [
                             VOMS_LIBS="$withval"
                    ]
            )
if test -z "$VOMS_LIBS" && test $voms_enable = 1; then
        AC_MSG_ERROR([no VOMS libraries directory found])
else
	AC_MSG_NOTICE([VOMS libraries directory: $VOMS_LIBS])
	VOMS_DEFINE="GLITE_VOMS"
fi
AC_SUBST(VOMS_LIBS)
AC_SUBST(VOMS_DEFINE)

#Set VOMS include path
AC_ARG_WITH(voms-include,
            [  --with-voms-include=VOMS_INCLUDE       Sets the VOMS include path],
                    [
                             VOMS_INCLUDE="$withval"
                    ]
            )
if test -z "$VOMS_INCLUDE" && test $voms_enable = 1; then
        AC_MSG_ERROR([no VOMS include directory found])
else
	AC_MSG_NOTICE([VOMS includes: $VOMS_INCLUDE])
fi
AC_SUBST(VOMS_INCLUDE)

# Set servers default listening port number
ws_port=11732
AC_ARG_WITH(ws-port,
	   [  --with-ws-port=NUMBER     Set server listening port number (default: 11732)],
	   [
	    ws_port="$withval"
           ]
           )
PLUGIN_DEFAULT_PORT=$ws_port
AC_SUBST(PLUGIN_DEFAULT_PORT)

ws_hostname=$HOSTNAME
AC_ARG_WITH(ws-hostname,
	   [  --with-ws-hostname=HOSTNAME     Set server FQDN (default: hostname)],
	   [
	    ws_hostname="$withval"
           ]
           )
PLUGIN_DEFAULT_HOSTNAME=$ws_hostname
AC_SUBST(PLUGIN_DEFAULT_HOSTNAME)

ws_protocol="https"
AC_ARG_WITH(ws-protocol,
	   [  --with-ws-protocol=PROTOCOL     Set web service protocol (default: https)],
	   [
	    ws_protocol="$withval"
           ]
           )
PLUGIN_DEFAULT_PROTOCOL=$ws_protocol
AC_SUBST(PLUGIN_DEFAULT_PROTOCOL)

AUTHORIZATION="$prefix/authz/dn.dat"
AC_SUBST(AUTHORIZATION) 
AUTHORIZATION_FILE="$prefix/authz/dn.dat"
AC_SUBST(AUTHORIZATION_FILE)

BLACK_LIST="$prefix/authz/black_dn.dat"
AC_SUBST(BLACK_LIST) 
BLACK_LIST_FILE="$prefix/authz/black_dn.dat"
AC_SUBST(BLACK_LIST_FILE)

AUTHORIZED_VO="$prefix/authz/vo.dat"
AC_SUBST(AUTHORIZED_VO) 
AUTHORIZED_VO_FILE="$prefix/authz/vo.dat"
AC_SUBST(AUTHORIZED_VO_FILE)

OPH_SERVER_LOCATION=$prefix
AC_SUBST(OPH_SERVER_LOCATION)

AC_ARG_WITH(framework_path,
	   [  --with-framework-path=PATH 		Location of oph-analytics-framework],
	   [
		framework_path="$withval"
	   ],
	   [
		framework_path="/usr/local/ophidia/oph-cluster/oph-analytics-framework"
	   ])
OPH_FRAMEWORK_LOCATION=${framework_path}
AC_SUBST(OPH_FRAMEWORK_LOCATION)

AC_ARG_WITH(web_server_url,
	   [  --with-web-server-url=URL 		Location of web server],
	   [
		web_server_url="$withval"
	   ],
	   [
		web_server_url="http://127.0.0.1"
	   ])
OPH_WEB_SERVER=${web_server_url}
AC_SUBST(OPH_WEB_SERVER)

AC_ARG_WITH(web_server_path,
	   [  --with-web-server-path=PATH 		Location of web server],
	   [
		web_server_path="$withval"
	   ],
	   [
		web_server_path="/var/www/html"
	   ])
OPH_WEB_SERVER_LOCATION=${web_server_path}
AC_SUBST(OPH_WEB_SERVER_LOCATION)

PKG_CHECK_MODULES(XML, libxml-2.0 >= 2.4)
AC_ARG_WITH(libxml_header_path,
	   [  --with-libxml-header-path=PATH 		Location of libxml2 includes directory],
	   [
		libxml_header_path="$withval"
	   ],
	   [
		libxml_header_path="$XML_CFLAGS"
	   ])
AC_ARG_WITH(libxml_lib_path,
	   [  --with-libxml-lib-path=PATH 		Location of libxml2.a],
	   [
		libxml_lib_path="$withval"
	   ],
	   [
		libxml_lib_path="$XML_LIBS"
	   ])

LIBXML_INCLUDE="$libxml_header_path"
AC_SUBST(LIBXML_INCLUDE)
LIBXML_LIB="$libxml_lib_path"
AC_SUBST(LIBXML_LIB)

PKG_CHECK_MODULES(CURL, libcurl >= 0.23)
AC_ARG_WITH(libcurl_header_path,
	   [  --with-libcurl-header-path=PATH 		Location of libcurl includes directory],
	   [
		libcurl_header_path="$withval"
	   ],
	   [
		libcurl_header_path="$CURL_CFLAGS"
	   ])
AC_ARG_WITH(libcurl_lib_path,
	   [  --with-libcurl-lib-path=PATH 		Location of libcurl.a],
	   [
		libcurl_lib_path="$withval"
	   ],
	   [
		libcurl_lib_path="$CURL_LIBS"
	   ])

LIBCURL_INCLUDE="$libcurl_header_path"
AC_SUBST(LIBCURL_INCLUDE)
LIBCURL_LIB="$libcurl_lib_path"
AC_SUBST(LIBCURL_LIB)

PKG_CHECK_MODULES(OPENSSL, openssl >= 1.0.0)
AC_ARG_WITH(libopenssl_header_path,
	   [  --with-libopenssl-header-path=PATH 		Location of openssl includes directory],
	   [
		libopenssl_header_path="$withval"
	   ],
	   [
		libopenssl_header_path="$OPENSSL_CFLAGS"
	   ])
AC_ARG_WITH(libopenssl_lib_path,
	   [  --with-libopenssl-lib-path=PATH 		Location of openssl],
	   [
		libopenssl_lib_path="$withval"
	   ],
 	   [
		libopenssl_lib_path="$OPENSSL_LIBS"
   	   ])
LIBSSL_INCLUDE="$libopenssl_header_path"
AC_SUBST(LIBSSL_INCLUDE)
LIBSSL_LIB="$libopenssl_lib_path"
AC_SUBST(LIBSSL_LIB)

PKG_CHECK_MODULES(SSH2, libssh2 >= 0.23)
AC_ARG_WITH(libssh2_header_path,
	   [  --with-libssh2-header-path=PATH 		Location of libssh2 includes directory],
	   [
		libssh2_header_path="$withval"
	   ],
     [
    libssh2_header_path="$SSH2_CFLAGS"
     ])
AC_ARG_WITH(libssh2_lib_path,
	   [  --with-libssh2-lib-path=PATH 		Location of libssh2],
	   [
		libssh2_lib_path="$withval"
	   ],
     [
    libssh2_lib_path="$SSH2_LIBS"
     ])
LIBSSH2_INCLUDE="$libssh2_header_path"
AC_SUBST(LIBSSH2_INCLUDE)
LIBSSH2_LIB="$libssh2_lib_path"
AC_SUBST(LIBSSH2_LIB)

have_soapcpp2=no
SOAPCPP2_PROG=
AC_ARG_WITH(soapcpp2_path,
           [  --with-soapcpp2-path=PATH  Set the soapcpp2 root dir],
           [
                soapcpp2_path="$withval"
		have_soapcpp2=yes
		SOAPCPP2_PROG="${withval}/bin/soapcpp2"
           ],
           [
                AC_PATH_PROG([SOAPCPP2_PROG], soapcpp2)
			          if test -n "$SOAPCPP2_PROG" ; then
				          have_soapcpp2=yes
              	fi
           ]
           )
if test "x${have_soapcpp2}" = "xyes"; then
	AC_MSG_NOTICE([SoapCPP2 available.])
else
	AC_MSG_ERROR([SoapCPP2 not found! Aborting configure!])
fi

PKG_CHECK_MODULES(JANSSON, jansson >= 2.3)
AC_ARG_WITH(jansson_header_path,
       [  --with-jansson-header-path=PATH        Location of Jansson includes directory],
       [
        jansson_header_path="$withval"
       ],
     [
    jansson_header_path="$JANSSON_CFLAGS"
     ])
AC_ARG_WITH(jansson_lib_path,
       [  --with-jansson-lib-path=PATH       Location of jansson lib],
       [
        jansson_lib_path="$withval"
       ],
     [
    jansson_lib_path="$JANSSON_LIBS"
     ])
JANSON_CFLAGS="$jansson_header_path"
AC_SUBST(JANSON_CFLAGS)
JANSON_LIBS="$jansson_lib_path"
AC_SUBST(JANSON_LIBS)
JANSSON_LIBDIR=`pkg-config --variable=libdir jansson`
AC_SUBST(JANSSON_LIBDIR)

case "${host}" in
        *-*-solaris*)   PLATFORM=SUN_OS
                        SAMPLE_EXTRA_LIBS="-lxnet -lsocket -lnsl"
                        ;;
        *-*-sysv5*)     PLATFORM=UNIXWARE ;;
        *-*-UnixWare*)  PLATFORM=UNIXWARE ;;
        *-*-unixware*)  PLATFORM=UNIXWARE ;;
        *-*-sco3.2v5*)  PLATFORM=OPENSERVER
                        SAMPLE_EXTRA_LIBS="-lsocket"
                        ;;
        *-*-linux*)     PLATFORM=LINUX
                                    if test "x$debug" = "xyes"; then
										OPT="-g3 -Wall -Wextra -O0 -DLOCAL_FRAMEWORK -DUSE_MPI"
									else
										OPT="-O2"
									fi
			            if test "x$optimization" = "xyes" ; then
			                 CFLAGS="-O3 -finline-functions -funswitch-loops -fgcse-after-reload -ftree-loop-linear -ftree-loop-im -ftree-loop-ivcanon -fivopts -ftree-vectorize -ftracer -fgcse-sm -fgcse-las -fgcse-after-reload -funroll-loops -freorder-blocks-and-partition -fweb"
			            fi
			            ;;
                *-*-cygwin*)    PLATFORM=CYGWIN
                        ;;
        *-*-freebsd*)   PLATFORM=FREEBSD ;;
        *-*-irix*)      PLATFORM=IRIX
                        ;;
        *-*-aix*)       PLATFORM=AIX
                      case "${host}" in
                         *-*-aix4.1*)   osver=AIX41;;
                         *-*-aix4.2*)   osver=AIX42;;
                         *-*-aix4.3*)   osver=AIX43;;
                         *-*-aix4.*)    osver=AIX43;;
                      esac;;
        *-sequent-*)    PLATFORM=PTX ;;
        *-*-hp*)        PLATFORM=HP_UX ;
                        case "${host}" in
                            *-*-hpux11*)  osver=HPUX11;;
                            *-*-hpux10*)  osver=HPUX10;;
                            *)            osver=HPUX11;;
                        esac;;
        *-*-mvs*)       PLATFORM=OS390 ;;
        *-*-os400*)     PLATFORM=OS400 ;;
        *-*-OS400*)     PLATFORM=OS400 ;;
        *-*-osf*)       PLATFORM=TRU64
				        OPT="-g3"
				        REENTRANT="1"
                               ;;
        *-apple-*)      PLATFORM=__APPLE__
				        OPT="-g3"
				        ;;
        *)              PLATFORM=UNKNOWN ;;
esac

AC_SUBST(SAMPLE_EXTRA_LIBS)
AC_SUBST(PLATFORM)
AC_SUBST(OPT)
AC_SUBST(REENTRANT)

AM_CONDITIONAL(VOMS, test $voms_enable = 1)

AC_CONFIG_FILES([etc/oph_server], [chmod 0755 etc/oph_server])

AC_OUTPUT([Makefile src/Makefile test/Makefile etc/server.conf etc/web/env.php etc/oph_server_logrotate])


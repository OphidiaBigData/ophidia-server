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

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . src test

include_HEADERS = src/oph_types.h src/oph_execute_main.h

sysconf_DATA = etc/*.conf etc/oph_server_logrotate

bindir=${prefix}/etc
bin_SCRIPTS = etc/oph_server

scriptdir=${prefix}/etc/script
dist_script_SCRIPTS = etc/script/*.sh

certdir = $(prefix)/etc/cert/
dist_cert_DATA =

logdir = $(prefix)/log/
dist_log_DATA =

xmldir = $(prefix)/etc/xml/
dist_xml_DATA = etc/xml/*.xml

dtddir = $(prefix)/etc/dtd/
dist_dtd_DATA = etc/dtd/*.dtd

rmsdir = $(prefix)/etc/rms/
dist_rms_DATA = etc/rms/*.conf

sessionsdir = $(OPH_WEB_SERVER_LOCATION)/sessions/
dist_sessions_DATA =

if OPH_WEB_ACCESS
webdir = $(OPH_WEB_SERVER_LOCATION)/
dist_web_DATA = etc/web/*.php etc/web/style.css etc/web/.htaccess
endif

AM_DEFAULT_VERBOSITY = 1
CODE_COVERAGE_LCOV_OPTIONS = --gcov-tool "$(GCOV)" --no-external
CODE_COVERAGE_BRANCH_COVERAGE = 1
CODE_COVERAGE_IGNORE_PATTERN = "*oph_server_test*"
@CODE_COVERAGE_RULES@

clean-local:
	-rm -f *~ authz/*~ etc/*~ etc/cert/*~ etc/dtd/*~ etc/rms/*~ etc/xml/*~

distclean-local:
	-rm -f *~ authz/*~ etc/*~ etc/cert/*~ etc/dtd/*~ etc/rms/*~ etc/xml/*~


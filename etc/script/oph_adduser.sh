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

#!/bin/bash

# Input parameters
PASSWD=${1}
SERVER=${2} 
PORT=11732

# Body
echo -e "# >>> Variables for Ophidia environment >>>\nexport PATH=\"/usr/local/ophidia/oph-terminal/bin/:\$PATH\"\nexport OPH_USER=${USER}\nexport OPH_PASSWD=\"${PASSWD}\"\nexport OPH_SERVER_PORT=${PORT}\nexport OPH_SERVER_HOST=${SERVER}\n# <<< Variables for Ophidia environment <<<" >> ${HOME}/.oph_profile
chmod 600 ${HOME}/.oph_profile

exit 0


#
#    Ophidia Server
#    Copyright (C) 2012-2023 CMCC Foundation
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

my_dir=$(dirname "$0")
. $my_dir/../server.conf

# Input parameters

# Const
fixString=
CHECKER=${OPH_EXTRA_LOCATION}/bin/squeue

# Body
${CHECKER} -o "%j %u"

exit $?


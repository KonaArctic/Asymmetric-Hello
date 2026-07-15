#!/bin/bash
set -o errexit -o pipefail
shopt -s expand_aliases extglob
IFS=
[[ ! $0 =~ / ]] ||
	cd ${0%/*}
[[ `ip address` =~ inet6\ ([^/]+)/[0-9]+\ scope\ global ]]
alias dig_remote=dig\ -p${1##*:}\ +subnet=${BASH_REMATCH[1]}/48\ +tcp\ @${1%:*}
for script in `pwd`/*/prepare.sh ; do
	cd ${script%/*}
	source $script
done

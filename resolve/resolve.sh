#!/bin/bash
set -o errexit -o pipefail
shopt -s expand_aliases extglob
IFS=
[[ ! $0 =~ / ]] ||
	cd ${0%/*}

# Resolve via remote and local DNS resolver.
[[ `ip address` =~ inet6\ ([^/]+)/[0-9]+\ scope\ global ]]
alias dig_remote=dig\ -p${1##*:}\ +subnet=${BASH_REMATCH[1]}/48\ +timeout=15\ @::1
alias dig=dig\ +ednsopt=65328:$2\ +timeout=5

# Try to guess if a destination is censored.
# You may need to change this depending on your circumstances.
ipaddr=`dig +short aaaa $3`
if [[ ! $ipaddr =~ ^[0-9a-f]{0,4}::[0-9a-f]{0,4}$ ]] ; then
	echo $ipaddr
	exit 0
fi

# Resolve
for script in `pwd`/*/resolve.sh ; do
	cd ${script%/*}
	stdout=`source $script $3`
	if [[ $stdout ]] ; then
		echo $stdout
		exit 0
	fi
done

# Default
dig_remote +short aaaa $3

exit 0

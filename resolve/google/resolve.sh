#!/bin/bash
set -o errexit
# Google services seem to live in AS15169.
# If this ever changes or found untrue this script will need to be adjusted.
if grepcidr -f as15169 <<< `dig_remote +short aaaa $1` > /dev/null ; then
	echo `< google`
fi

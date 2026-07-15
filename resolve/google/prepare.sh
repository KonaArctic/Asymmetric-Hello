#!/bin/bash
set -o errexit
curl --fail --location --silent https://stat.ripe.net/data/announced-prefixes/data.json\?resource=15169 |
grep --extended-regexp --ignore-case --only-matching \[0-9a-f:\]\*:\[0-9a-f:\]\*/\[0-9\]+ > as15169
dig_remote +short aaaa gstatic.com |
{	target=( )
	while read -r ipaddr ; do
		target+=( $ipaddr/120 )
	done
	nmap --noninteractive --open -6 -Pn -n -oG - -p443 -sT ${target[*]}
} |
while read -r status ; do
	[[ $status =~ Host:\ ([^\ ]+)\ \(\)\	Ports:\ 443/open/tcp/ ]] ||
		continue
	if curl --connect-timeout 5 --connect-to gstatic.com:443:\[${BASH_REMATCH[1]}\]:443 --fail --noproxy \* --silent https://gstatic.com/robots.txt > /dev/null ; then
		echo ${BASH_REMATCH[1]}
	fi
done > google
if [[ ! -s google ]] then
	echo "Google: no addresses discovered" >&2
	exit 1
fi

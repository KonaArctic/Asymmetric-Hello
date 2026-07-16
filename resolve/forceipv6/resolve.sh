#!/bin/bash
set -o errexit
if [[ `dig_remote +short aaaa $1` =~ : ]] ; then
	return 0
fi
for domain in $1 \*.${1#*.} `dig_remote +short cname \$1`; do
	record=`grep \${domain}rpz.delegacy.monostack.org.\\ 3600\\ IN < delegacy.zone` ||
		continue
	if [[ $record =~ AAAA[[:space:]]+ ]] ; then
		grep --extended-regexp ${domain}rpz.delegacy.monostack.org.\ 3600\ IN[[:space:]]+AAAA < delegacy.zone
		return 0
	fi
	if [[ $record =~ CNAME[[:space:]]+(.*) ]] ; then
		dig_remote +short aaaa ${BASH_REMATCH[1]}
		return 0
	fi
done

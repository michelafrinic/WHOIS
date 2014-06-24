#!/bin/sh
# this script dumps the schemas of the databases used by the WHOIS
declare -a arr=("ACL_LOCAL" "AFRINICDB" "DNSCHECK_LOCAL" "INTERNALS_LOCAL" "WHOIS_LOCAL" "MAILUPDATES_LOCAL")

for i in "${arr[@]}"
do
  mysqldump -u dbint --no-data ${i} > ${i}.sql
done

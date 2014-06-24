#!/bin/bash

read -s -p "Enter mysql root password: " mysqlPwd

# create and init DBs
mysql -u root -p$mysqlPwd < CREATE_DBS.sql

# create Dbs schemas
mysql -u root -p$mysqlPwd -D ACL_LOCAL < ACL_LOCAL.sql
mysql -u root -p$mysqlPwd -D AFRINICDB < AFRINICDB.sql
mysql -u root -p$mysqlPwd -D DNSCHECK_LOCAL < DNSCHECK_LOCAL.sql
mysql -u root -p$mysqlPwd -D INTERNALS_LOCAL < INTERNALS_LOCAL.sql 
mysql -u root -p$mysqlPwd -D MAILUPDATES_LOCAL < MAILUPDATES_LOCAL.sql 
mysql -u root -p$mysqlPwd -D WHOIS_LOCAL < WHOIS_LOCAL.sql

# update versions
mysql -u root -p$mysqlPwd -D AFRINICDB < UPDATE_VERSION.sql

echo "Done."
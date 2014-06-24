CREATE DATABASE ACL_LOCAL;
CREATE DATABASE AFRINICDB;
CREATE DATABASE DNSCHECK_LOCAL;
CREATE DATABASE INTERNALS_LOCAL;
CREATE DATABASE MAILUPDATES_LOCAL;
CREATE DATABASE WHOIS_LOCAL;

grant all on ACL_LOCAL.* to 'dbint'@'localhost' identified by '';
grant all on AFRINICDB.* to 'dbint'@'localhost' identified by '';
grant all on DNSCHECK_LOCAL.* to 'dint'@'localhost' identified by '';
grant all on INTERNALS_LOCAL.* to 'dbint'@'localhost' identified by '';
grant all on MAILUPDATES_LOCAL.* to 'dbint'@'localhost' identified by '';
grant all on WHOIS_LOCAL.* to 'dbint'@'localhost' identified by '';

flush privileges;
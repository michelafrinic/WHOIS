-- last version is whois-1.70
SET @whoisversion = 'whois-1.70';

INSERT INTO version (version) VALUES (@whoisversion);
use ACL_LOCAL;
INSERT INTO version (version) VALUES (@whoisversion);
use DNSCHECK_LOCAL;
INSERT INTO version (version) VALUES (@whoisversion);
use INTERNALS_LOCAL;
INSERT INTO version (version) VALUES (@whoisversion);
use MAILUPDATES_LOCAL;
INSERT INTO version (version) VALUES (@whoisversion);
use WHOIS_LOCAL;
INSERT INTO version (version) VALUES (@whoisversion);
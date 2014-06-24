-- MySQL dump 10.13  Distrib 5.6.17, for osx10.7 (x86_64)
--
-- Host: localhost    Database: AFRINICDB
-- ------------------------------------------------------
-- Server version	5.6.17

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `aaa`
--

DROP TABLE IF EXISTS `aaa`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `aaa` (
  `prefix` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `source` varchar(32) NOT NULL DEFAULT '',
  `ripupdate` tinyint(3) NOT NULL DEFAULT '0',
  `mirror` tinyint(3) NOT NULL DEFAULT '0',
  `comment` longblob,
  PRIMARY KEY (`prefix`,`prefix_length`,`source`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `aaa6`
--

DROP TABLE IF EXISTS `aaa6`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `aaa6` (
  `prefix1` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix2` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix3` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix4` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `source` varchar(32) NOT NULL DEFAULT '',
  `ripupdate` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `mirror` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `comment` longblob,
  PRIMARY KEY (`prefix1`,`prefix2`,`prefix3`,`prefix4`,`prefix_length`,`source`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `abuse_c`
--

DROP TABLE IF EXISTS `abuse_c`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `abuse_c` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `contact_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`contact_id`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `abuse_mailbox`
--

DROP TABLE IF EXISTS `abuse_mailbox`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `abuse_mailbox` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `abuse_mailbox` varchar(80) NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`abuse_mailbox`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `access`
--

DROP TABLE IF EXISTS `access`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `access` (
  `prefix` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `connections` int(4) unsigned NOT NULL DEFAULT '0',
  `addr_passes` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `denials` int(4) unsigned NOT NULL DEFAULT '0',
  `queries` int(4) unsigned NOT NULL DEFAULT '0',
  `referrals` int(4) unsigned NOT NULL DEFAULT '0',
  `public_objects` int(6) unsigned NOT NULL DEFAULT '0',
  `private_objects` int(6) unsigned NOT NULL DEFAULT '0',
  `public_bonus` double NOT NULL DEFAULT '0',
  `private_bonus` double NOT NULL DEFAULT '0',
  `timestamp` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`prefix`,`prefix_length`),
  KEY `access_timestamp` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `access6`
--

DROP TABLE IF EXISTS `access6`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `access6` (
  `prefix1` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix2` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix3` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix4` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `connections` int(4) unsigned NOT NULL DEFAULT '0',
  `addr_passes` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `denials` int(4) unsigned NOT NULL DEFAULT '0',
  `queries` int(4) unsigned NOT NULL DEFAULT '0',
  `referrals` int(4) unsigned NOT NULL DEFAULT '0',
  `public_objects` int(6) unsigned NOT NULL DEFAULT '0',
  `private_objects` int(6) unsigned NOT NULL DEFAULT '0',
  `public_bonus` double NOT NULL DEFAULT '0',
  `private_bonus` double NOT NULL DEFAULT '0',
  `timestamp` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`prefix1`,`prefix2`,`prefix3`,`prefix4`,`prefix_length`),
  KEY `access_timestamp` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `acl`
--

DROP TABLE IF EXISTS `acl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acl` (
  `prefix` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `maxbonus` int(10) NOT NULL DEFAULT '0',
  `maxpublic` int(10) DEFAULT '-1',
  `maxdenials` int(10) unsigned NOT NULL DEFAULT '0',
  `deny` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `trustpass` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `threshold` tinyint(3) unsigned NOT NULL DEFAULT '4',
  `maxconn` tinyint(3) unsigned NOT NULL DEFAULT '6',
  `comment` longblob,
  PRIMARY KEY (`prefix`,`prefix_length`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `acl6`
--

DROP TABLE IF EXISTS `acl6`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acl6` (
  `prefix1` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix2` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix3` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix4` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `maxbonus` int(10) NOT NULL DEFAULT '0',
  `maxpublic` int(10) DEFAULT '-1',
  `maxdenials` int(10) unsigned NOT NULL DEFAULT '0',
  `deny` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `trustpass` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `threshold` tinyint(3) unsigned NOT NULL DEFAULT '4',
  `maxconn` tinyint(3) unsigned NOT NULL DEFAULT '6',
  `comment` longblob,
  PRIMARY KEY (`prefix1`,`prefix2`,`prefix3`,`prefix4`,`prefix_length`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `admin_c`
--

DROP TABLE IF EXISTS `admin_c`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `admin_c` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `pe_ro_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`pe_ro_id`,`object_id`),
  KEY `object_type` (`object_type`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `as_block`
--

DROP TABLE IF EXISTS `as_block`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `as_block` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `begin_as` int(10) unsigned NOT NULL DEFAULT '0',
  `end_as` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `as_set`
--

DROP TABLE IF EXISTS `as_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `as_set` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `as_set` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `as_set` (`as_set`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `aut_num`
--

DROP TABLE IF EXISTS `aut_num`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `aut_num` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `aut_num` char(13) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `aut_num` (`aut_num`),
  KEY `thread_id` (`thread_id`),
  KEY `thread_id_2` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth`
--

DROP TABLE IF EXISTS `auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `auth` varchar(90) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`auth`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_override`
--

DROP TABLE IF EXISTS `auth_override`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_override` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `date` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`date`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `author`
--

DROP TABLE IF EXISTS `author`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `author` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `pe_ro_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`pe_ro_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `domain`
--

DROP TABLE IF EXISTS `domain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `domain` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(254) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `domain` (`domain`(16)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ds_rdata`
--

DROP TABLE IF EXISTS `ds_rdata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ds_rdata` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `ds_rdata` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`ds_rdata`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dummy_rec`
--

DROP TABLE IF EXISTS `dummy_rec`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `dummy_rec` (
  `transaction_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`transaction_id`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `e_mail`
--

DROP TABLE IF EXISTS `e_mail`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `e_mail` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `e_mail` varchar(80) NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`e_mail`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `failed_transaction`
--

DROP TABLE IF EXISTS `failed_transaction`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `failed_transaction` (
  `thread_id` int(10) unsigned NOT NULL DEFAULT '0',
  `serial_id` int(10) unsigned NOT NULL DEFAULT '0',
  `timestamp` int(10) unsigned NOT NULL DEFAULT '0',
  `object` longblob NOT NULL,
  PRIMARY KEY (`serial_id`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `filter_set`
--

DROP TABLE IF EXISTS `filter_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `filter_set` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `filter_set` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `filter_set` (`filter_set`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `fingerpr`
--

DROP TABLE IF EXISTS `fingerpr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fingerpr` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `fingerpr` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`fingerpr`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `form`
--

DROP TABLE IF EXISTS `form`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `form` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `form_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`form_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `history`
--

DROP TABLE IF EXISTS `history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `history` (
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `sequence_id` int(10) unsigned NOT NULL DEFAULT '0',
  `timestamp` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `object` longblob NOT NULL,
  `pkey` varchar(254) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`,`sequence_id`),
  KEY `pkey` (`pkey`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ifaddr`
--

DROP TABLE IF EXISTS `ifaddr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ifaddr` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `ifaddr` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`ifaddr`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inaddr_arpa`
--

DROP TABLE IF EXISTS `inaddr_arpa`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inaddr_arpa` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inet6num`
--

DROP TABLE IF EXISTS `inet6num`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inet6num` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `i6_msb` varchar(20) NOT NULL DEFAULT '',
  `i6_lsb` varchar(20) NOT NULL DEFAULT '',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `netname` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `netname` (`netname`(8)),
  KEY `i6_msb` (`i6_msb`),
  KEY `i6_lsb` (`i6_lsb`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inet_rtr`
--

DROP TABLE IF EXISTS `inet_rtr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inet_rtr` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `inet_rtr` varchar(254) NOT NULL DEFAULT '',
  `local_as` varchar(13) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `inet_rtr` (`inet_rtr`(25)),
  KEY `local_as` (`local_as`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inetnum`
--

DROP TABLE IF EXISTS `inetnum`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inetnum` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `begin_in` int(10) unsigned NOT NULL DEFAULT '0',
  `end_in` int(10) unsigned NOT NULL DEFAULT '0',
  `netname` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `netname` (`netname`(8)),
  KEY `begin_in` (`begin_in`),
  KEY `end_in` (`end_in`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `interface`
--

DROP TABLE IF EXISTS `interface`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `interface` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `interface_v6_msp` varchar(20) NOT NULL DEFAULT '',
  `interface_v6_lsp` varchar(20) NOT NULL DEFAULT '',
  `interface_v4` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`interface_v6_lsp`,`interface_v6_msp`,`interface_v4`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ip6int`
--

DROP TABLE IF EXISTS `ip6int`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ip6int` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `msb` varchar(20) NOT NULL DEFAULT '',
  `lsb` varchar(20) NOT NULL DEFAULT '',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `irt`
--

DROP TABLE IF EXISTS `irt`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `irt` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `irt` varchar(80) NOT NULL DEFAULT '0',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `irt` (`irt`(25))
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `irt_nfy`
--

DROP TABLE IF EXISTS `irt_nfy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `irt_nfy` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `irt_nfy` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`irt_nfy`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `key_cert`
--

DROP TABLE IF EXISTS `key_cert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `key_cert` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `key_cert` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `key_cert` (`key_cert`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `last`
--

DROP TABLE IF EXISTS `last`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `last` (
  `object_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `sequence_id` int(10) unsigned NOT NULL DEFAULT '1',
  `timestamp` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `object` longblob NOT NULL,
  `pkey` varchar(254) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`,`sequence_id`),
  KEY `pkey` (`pkey`)
) ENGINE=MyISAM AUTO_INCREMENT=166734 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `limerick`
--

DROP TABLE IF EXISTS `limerick`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `limerick` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `limerick` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `limerick` (`limerick`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mbrs_by_ref`
--

DROP TABLE IF EXISTS `mbrs_by_ref`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mbrs_by_ref` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `member_of`
--

DROP TABLE IF EXISTS `member_of`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `member_of` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `set_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`set_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_by`
--

DROP TABLE IF EXISTS `mnt_by`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_by` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_domains`
--

DROP TABLE IF EXISTS `mnt_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_domains` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_irt`
--

DROP TABLE IF EXISTS `mnt_irt`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_irt` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `irt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`irt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_lower`
--

DROP TABLE IF EXISTS `mnt_lower`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_lower` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_nfy`
--

DROP TABLE IF EXISTS `mnt_nfy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_nfy` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_nfy` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`mnt_nfy`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_ref`
--

DROP TABLE IF EXISTS `mnt_ref`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_ref` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_routes`
--

DROP TABLE IF EXISTS `mnt_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_routes` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mnt_routes6`
--

DROP TABLE IF EXISTS `mnt_routes6`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mnt_routes6` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mntner`
--

DROP TABLE IF EXISTS `mntner`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mntner` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mntner` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `mntner` (`mntner`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `names`
--

DROP TABLE IF EXISTS `names`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `names` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `name` varchar(64) NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`name`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nic_hdl`
--

DROP TABLE IF EXISTS `nic_hdl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nic_hdl` (
  `thread_id` int(10) unsigned NOT NULL DEFAULT '0',
  `range_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `range_start` int(10) unsigned NOT NULL DEFAULT '0',
  `range_end` int(10) unsigned NOT NULL DEFAULT '0',
  `space` char(4) NOT NULL DEFAULT '',
  `source` char(10) NOT NULL DEFAULT '',
  PRIMARY KEY (`range_id`,`range_start`,`range_end`),
  KEY `range_start` (`range_start`),
  KEY `range_end` (`range_end`),
  KEY `space` (`space`,`source`(5)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM AUTO_INCREMENT=6532 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `notify`
--

DROP TABLE IF EXISTS `notify`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notify` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `notify` varchar(80) NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`notify`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nserver`
--

DROP TABLE IF EXISTS `nserver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nserver` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `host` varchar(254) NOT NULL DEFAULT '',
  PRIMARY KEY (`host`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_order`
--

DROP TABLE IF EXISTS `object_order`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `object_order` (
  `object_type` int(11) NOT NULL DEFAULT '0',
  `order_code` int(11) DEFAULT NULL,
  PRIMARY KEY (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `org`
--

DROP TABLE IF EXISTS `org`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `org` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `org_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`org_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `org_name`
--

DROP TABLE IF EXISTS `org_name`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `org_name` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `name` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`name`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `organisation`
--

DROP TABLE IF EXISTS `organisation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `organisation` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `organisation` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`organisation`,`object_id`),
  KEY `organisation` (`organisation`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `organisation_id`
--

DROP TABLE IF EXISTS `organisation_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `organisation_id` (
  `thread_id` int(10) unsigned NOT NULL DEFAULT '0',
  `range_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `range_end` int(10) unsigned NOT NULL DEFAULT '0',
  `space` char(4) NOT NULL DEFAULT '',
  `source` char(10) NOT NULL DEFAULT '',
  PRIMARY KEY (`range_id`,`range_end`),
  KEY `range_end` (`range_end`),
  KEY `space` (`space`,`source`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM AUTO_INCREMENT=937 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `peering_set`
--

DROP TABLE IF EXISTS `peering_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `peering_set` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `peering_set` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `peering_set` (`peering_set`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `person_role`
--

DROP TABLE IF EXISTS `person_role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `person_role` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `nic_hdl` varchar(30) NOT NULL DEFAULT '',
  `object_type` tinyint(4) unsigned NOT NULL DEFAULT '0',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `nic_hdl` (`nic_hdl`(20)),
  KEY `object_type` (`object_type`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ping_hdl`
--

DROP TABLE IF EXISTS `ping_hdl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ping_hdl` (
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `pe_ro_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`pe_ro_id`,`object_id`),
  KEY `object_type` (`object_type`),
  KEY `object_id` (`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `poem`
--

DROP TABLE IF EXISTS `poem`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `poem` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `poem` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`),
  KEY `poem` (`poem`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `poetic_form`
--

DROP TABLE IF EXISTS `poetic_form`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `poetic_form` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `poetic_form` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`poetic_form`),
  KEY `poetic_form` (`poetic_form`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ref_nfy`
--

DROP TABLE IF EXISTS `ref_nfy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ref_nfy` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `ref_nfy` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`ref_nfy`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `refer`
--

DROP TABLE IF EXISTS `refer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `refer` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `port` int(5) unsigned NOT NULL DEFAULT '43',
  `host` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`object_id`,`host`,`port`,`type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `referral_by`
--

DROP TABLE IF EXISTS `referral_by`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `referral_by` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `mnt_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`mnt_id`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `object_type` (`object_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rev_srv`
--

DROP TABLE IF EXISTS `rev_srv`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rev_srv` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `rev_srv` varchar(254) NOT NULL DEFAULT '',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`rev_srv`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `route`
--

DROP TABLE IF EXISTS `route`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `route` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix` int(10) unsigned NOT NULL DEFAULT '0',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `origin` char(13) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `origin` (`origin`,`prefix`,`prefix_length`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `route6`
--

DROP TABLE IF EXISTS `route6`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `route6` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `r6_msb` varchar(20) NOT NULL DEFAULT '',
  `r6_lsb` varchar(20) NOT NULL DEFAULT '',
  `prefix_length` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `origin` char(13) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `origin` (`origin`,`r6_msb`,`r6_lsb`,`prefix_length`),
  KEY `r6_msb` (`r6_msb`),
  KEY `r6_lsb` (`r6_lsb`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `route_set`
--

DROP TABLE IF EXISTS `route_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `route_set` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `route_set` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `route_set` (`route_set`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rtr_set`
--

DROP TABLE IF EXISTS `rtr_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rtr_set` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `rtr_set` varchar(80) NOT NULL DEFAULT '',
  `dummy` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`object_id`),
  KEY `rtr_set` (`rtr_set`(25)),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `serials`
--

DROP TABLE IF EXISTS `serials`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `serials` (
  `thread_id` int(10) unsigned NOT NULL DEFAULT '0',
  `serial_id` int(11) NOT NULL AUTO_INCREMENT,
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `sequence_id` int(10) unsigned NOT NULL DEFAULT '0',
  `atlast` tinyint(4) unsigned NOT NULL DEFAULT '0',
  `operation` tinyint(4) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`serial_id`),
  KEY `object` (`object_id`,`sequence_id`),
  KEY `thread_id` (`thread_id`)
) ENGINE=MyISAM AUTO_INCREMENT=326671 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sub_dom`
--

DROP TABLE IF EXISTS `sub_dom`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sub_dom` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(254) NOT NULL DEFAULT '',
  PRIMARY KEY (`domain`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tags` (
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `tag_id` varchar(50) NOT NULL DEFAULT '',
  `data` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`object_id`,`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tech_c`
--

DROP TABLE IF EXISTS `tech_c`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tech_c` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `pe_ro_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`pe_ro_id`,`object_id`),
  KEY `object_type` (`object_type`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tid`
--

DROP TABLE IF EXISTS `tid`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tid` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`ID`)
) ENGINE=MyISAM AUTO_INCREMENT=327859 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `transaction_rec`
--

DROP TABLE IF EXISTS `transaction_rec`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `transaction_rec` (
  `transaction_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `sequence_id` int(10) unsigned NOT NULL DEFAULT '1',
  `serial_id` int(10) unsigned NOT NULL DEFAULT '1',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `save` varchar(255) NOT NULL DEFAULT '',
  `error_script` blob NOT NULL,
  `mode` tinyint(4) unsigned NOT NULL DEFAULT '0',
  `succeeded` tinyint(4) unsigned NOT NULL DEFAULT '0',
  `action` tinyint(4) unsigned NOT NULL DEFAULT '0',
  `status` int(10) unsigned NOT NULL DEFAULT '0',
  `clean` tinyint(3) NOT NULL DEFAULT '0',
  PRIMARY KEY (`transaction_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `upd_to`
--

DROP TABLE IF EXISTS `upd_to`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `upd_to` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `upd_to` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`upd_to`,`object_id`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `update_lock`
--

DROP TABLE IF EXISTS `update_lock`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `update_lock` (
  `global_lock` int(11) NOT NULL,
  PRIMARY KEY (`global_lock`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `version`
--

DROP TABLE IF EXISTS `version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `version` (
  `version` varchar(80) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `x509`
--

DROP TABLE IF EXISTS `x509`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `x509` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `keycert_id` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`keycert_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zone_c`
--

DROP TABLE IF EXISTS `zone_c`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zone_c` (
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `object_id` int(10) unsigned NOT NULL DEFAULT '0',
  `pe_ro_id` int(10) unsigned NOT NULL DEFAULT '0',
  `object_type` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`pe_ro_id`,`object_id`),
  KEY `object_type` (`object_type`),
  KEY `object_id` (`object_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2014-06-24  9:14:53

--
--    Ophidia Server
--    Copyright (C) 2012-2020 CMCC Foundation
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

-- Use:
--
-- > sqlite ophidiadb
-- sqlite> .read ophidiadb.sql

CREATE TABLE `country` (
	idcountry INTEGER PRIMARY KEY NOT NULL,
	name VARCHAR(64) NOT NULL);
INSERT INTO `country` VALUES (245,'Afghanistan, Islamic State of'),(246,'Albania'),(247,'Algeria'),(248,'American Samoa'),(249,'Andorra, Principality of'),(250,'Angola'),(251,'Anguilla'),(252,'Antarctica'),(253,'Antigua and Barbuda'),(254,'Argentina'),(255,'Armenia'),(256,'Aruba'),(257,'Australia'),(258,'Austria'),(259,'Azerbaidjan'),(260,'Bahamas'),(261,'Bahrain'),(262,'Bangladesh'),(263,'Barbados'),(264,'Belarus'),(265,'Belgium'),(266,'Belize'),(267,'Benin'),(268,'Bermuda'),(269,'Bhutan'),(270,'Bolivia'),(271,'Bosnia-Herzegovina'),(272,'Botswana'),(273,'Bouvet Island'),(274,'Brazil'),(275,'British Indian Ocean Territory'),(276,'Brunei Darussalam'),(277,'Bulgaria'),(278,'Burkina Faso'),(279,'Burundi'),(280,'Cambodia, Kingdom of'),(281,'Cameroon'),(282,'Canada'),(283,'Cape Verde'),(284,'Cayman Islands'),(285,'Central African Republic'),(286,'Chad'),(287,'Chile'),(288,'China'),(289,'Christmas Island'),(290,'Cocos (Keeling) Islands'),(291,'Colombia'),(292,'Comoros'),(293,'Congo'),(294,'Congo, The Democratic Republic of the'),(295,'Cook Islands'),(296,'Costa Rica'),(297,'Croatia'),(298,'Cuba'),(299,'Cyprus'),(300,'Czech Republic'),(301,'Denmark'),(302,'Djibouti'),(303,'Dominica'),(304,'Dominican Republic'),(305,'East Timor'),(306,'Ecuador'),(307,'Egypt'),(308,'El Salvador'),(309,'Equatorial Guinea'),(310,'Eritrea'),(311,'Estonia'),(312,'Ethiopia'),(313,'Falkland Islands'),(314,'Faroe Islands'),(315,'Fiji'),(316,'Finland'),(317,'Former Czechoslovakia'),(318,'Former USSR'),(319,'France'),(320,'France (European Territory)'),(321,'French Guyana'),(322,'French Southern Territories'),(323,'Gabon'),(324,'Gambia'),(325,'Georgia'),(326,'Germany'),(327,'Ghana'),(328,'Gibraltar'),(329,'Great Britain'),(330,'Greece'),(331,'Greenland'),(332,'Grenada'),(333,'Guadeloupe (French)'),(334,'Guam (USA)'),(335,'Guatemala'),(336,'Guinea'),(337,'Guinea Bissau'),(338,'Guyana'),(339,'Haiti'),(340,'Heard and McDonald Islands'),(341,'Holy See (Vatican City State)'),(342,'Honduras'),(343,'Hong Kong'),(344,'Hungary'),(345,'Iceland'),(346,'India'),(347,'Indonesia'),(348,'Iran'),(349,'Iraq'),(350,'Ireland'),(351,'Israel'),(352,'Italy'),(353,'Ivory Coast'),(354,'Jamaica'),(355,'Japan'),(356,'Jordan'),(357,'Kazakhstan'),(358,'Kenya'),(359,'Kiribati'),(360,'Kuwait'),(361,'Kyrgyz Republic (Kyrgyzstan)'),(362,'Laos'),(363,'Latvia'),(364,'Lebanon'),(365,'Lesotho'),(366,'Liberia'),(367,'Libya'),(368,'Liechtenstein'),(369,'Lithuania'),(370,'Luxembourg'),(371,'Macau'),(372,'Macedonia'),(373,'Madagascar'),(374,'Malawi'),(375,'Malaysia'),(376,'Maldives'),(377,'Mali'),(378,'Malta'),(379,'Marshall Islands'),(380,'Martinique (French)'),(381,'Mauritania'),(382,'Mauritius'),(383,'Mayotte'),(384,'Mexico'),(385,'Micronesia'),(386,'Moldavia'),(387,'Monaco'),(388,'Mongolia'),(389,'Montserrat'),(390,'Morocco'),(391,'Mozambique'),(392,'Myanmar'),(393,'Namibia'),(394,'Nauru'),(395,'Nepal'),(396,'Netherlands'),(397,'Netherlands Antilles'),(398,'Neutral Zone'),(399,'New Caledonia (French)'),(400,'New Zealand'),(401,'Nicaragua'),(402,'Niger'),(403,'Nigeria'),(404,'Niue'),(405,'Norfolk Island'),(406,'North Korea'),(407,'Northern Mariana Islands'),(408,'Norway'),(409,'Oman'),(410,'Pakistan'),(411,'Palau'),(412,'Panama'),(413,'Papua New Guinea'),(414,'Paraguay'),(415,'Peru'),(416,'Philippines'),(417,'Pitcairn Island'),(418,'Poland'),(419,'Polynesia (French)'),(420,'Portugal'),(421,'Puerto Rico'),(422,'Qatar'),(423,'Reunion (French)'),(424,'Romania'),(425,'Russian Federation'),(426,'Rwanda'),(427,'S. Georgia & S. Sandwich Isls.'),(428,'Saint Helena'),(429,'Saint Kitts & Nevis Anguilla'),(430,'Saint Lucia'),(431,'Saint Pierre and Miquelon'),(432,'Saint Tome (Sao Tome) and Principe'),(433,'Saint Vincent & Grenadines'),(434,'Samoa'),(435,'San Marino'),(436,'Saudi Arabia'),(437,'Senegal'),(438,'Seychelles'),(439,'Sierra Leone'),(440,'Singapore'),(441,'Slovak Republic'),(442,'Slovenia'),(443,'Solomon Islands'),(444,'Somalia'),(445,'South Africa'),(446,'South Korea'),(447,'Spain'),(448,'Sri Lanka'),(449,'Sudan'),(450,'Suriname'),(451,'Svalbard and Jan Mayen Islands'),(452,'Swaziland'),(453,'Sweden'),(454,'Switzerland'),(455,'Syria'),(456,'Tadjikistan'),(457,'Taiwan'),(458,'Tanzania'),(459,'Thailand'),(460,'Togo'),(461,'Tokelau'),(462,'Tonga'),(463,'Trinidad and Tobago'),(464,'Tunisia'),(465,'Turkey'),(466,'Turkmenistan'),(467,'Turks and Caicos Islands'),(468,'Tuvalu'),(469,'Uganda'),(470,'Ukraine'),(471,'United Arab Emirates'),(472,'United Kingdom'),(473,'United States'),(474,'Uruguay'),(475,'USA Minor Outlying Islands'),(476,'Uzbekistan'),(477,'Vanuatu'),(478,'Venezuela'),(479,'Vietnam'),(480,'Virgin Islands (British)'),(481,'Virgin Islands (USA)'),(482,'Wallis and Futuna Islands'),(483,'Western Sahara'),(484,'Yemen'),(485,'Yugoslavia'),(486,'Zaire'),(487,'Zambia'),(488,'Zimbabwe');

CREATE TABLE IF NOT EXISTS user(
	iduser INTEGER PRIMARY KEY NOT NULL,
	name VARCHAR(64) DEFAULT NULL,
	surname VARCHAR(64) DEFAULT NULL,
	mail VARCHAR(64) DEFAULT NULL,
	username VARCHAR(256) NOT NULL,
	password VARCHAR(64) DEFAULT NULL,
	registrationdate INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
	accountcertified INTEGER NOT NULL DEFAULT 0,
	idcountry INTEGER DEFAULT NULL,
	maxhosts INTEGER DEFAULT 0,
	CONSTRAINT `idcountry_u` FOREIGN KEY (`idcountry`) REFERENCES `country` (`idcountry`) ON DELETE SET NULL ON UPDATE CASCADE);
INSERT INTO `user` (`accountcertified`, `username`) VALUES (1, 'admin'), (1, 'oph-test');

CREATE TABLE IF NOT EXISTS session(
	idsession INTEGER PRIMARY KEY NOT NULL,
	iduser INTEGER NOT NULL,
	idfolder INTEGER DEFAULT NULL,
	sessionid VARCHAR(1024) NOT NULL,
	label VARCHAR(256) DEFAULT NULL,
	creationdate INTEGER DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS job(
	idjob INTEGER PRIMARY KEY NOT NULL,
	idparent INTEGER DEFAULT NULL,
	markerid INTEGER NOT NULL,
	workflowid INTEGER DEFAULT NULL,
	idsession INTEGER DEFAULT NULL,
	iduser INTEGER,
	creationdate INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
	status VARCHAR(64) NOT NULL,
	submissionstring VARCHAR(2048) DEFAULT NULL,
	timestart INTEGER DEFAULT NULL,
	timeend INTEGER DEFAULT NULL,
	nchildrentotal INTEGER DEFAULT NULL,
	nchildrencompleted INTEGER DEFAULT NULL,
	CONSTRAINT `idparent_j` FOREIGN KEY (`idparent`) REFERENCES `job` (`idjob`) ON DELETE CASCADE ON UPDATE CASCADE,
 	CONSTRAINT `idsession_j` FOREIGN KEY (`idsession`) REFERENCES `session` (`idsession`) ON DELETE CASCADE ON UPDATE CASCADE);

CREATE TABLE IF NOT EXISTS jobaccounting(
	idjob INTEGER PRIMARY KEY NOT NULL,
	idparent INTEGER DEFAULT NULL,
	markerid INTEGER NOT NULL,
	workflowid INTEGER DEFAULT NULL,
	idsession INTEGER DEFAULT NULL,
	iduser INTEGER DEFAULT NULL,
	creationdate INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
	status VARCHAR(64) NOT NULL,
	submissionstring VARCHAR(2048) DEFAULT NULL,
	timestart INTEGER DEFAULT NULL,
	timeend INTEGER DEFAULT NULL,
	nchildrentotal INTEGER DEFAULT NULL,
	nchildrencompleted INTEGER DEFAULT NULL,
	CONSTRAINT `idparent_ja` FOREIGN KEY (`idparent`) REFERENCES `jobaccounting` (`idjob`) ON DELETE CASCADE ON UPDATE CASCADE,
 	CONSTRAINT `idsession_ja` FOREIGN KEY (`idsession`) REFERENCES `session` (`idsession`) ON DELETE SET NULL ON UPDATE CASCADE);


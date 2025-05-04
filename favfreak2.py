#!/usr/bin/env python3

import json
import hashlib
import argparse
import codecs
import mmh3
import os
import requests
import sys
import shodan
from pathlib import Path
from multiprocessing.pool import ThreadPool
from time import time as timer
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# isable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

md5_FINGERPRINTS = {
  "6399cc480d494bf1fcd7d16c42b1c11b" : "penguin",
  "09b565a51e14b721a323f0ba44b2982a" : "Google web server",
  "506190fc55ceaa132f1bc305ed8472ca" : "SocialText",
  "2cc15cfae55e2bb2d85b57e5b5bc3371" : "PHPwiki (1.3.14) / gforge (4.6.99+svn6496) - wiki",
  "389a8816c5b87685de7d8d5fec96c85b" : "XOOPS cms",
  "f1876a80546b3986dbb79bad727b0374" : "NetScreen WebUI or 3Com Router",
  "226ffc5e483b85ec261654fe255e60be" : "Netscape 4.1",
  "b25dbe60830705d98ba3aaf0568c456a" : "Netscape iPlanet 6.0",
  "41e2c893098b3ed9fc14b821a2e14e73" : "Netscape 6.0 (AOL)",
  "a28ebcac852795fe30d8e99a23d377c1" : "SunOne 6.1",
  "71e30c507ca3fa005e2d1322a5aa8fb2" : "Apache on Redhat",
  "d41d8cd98f00b204e9800998ecf8427e" : "Zero byte favicon",
  "dcea02a5797ce9e36f19b7590752563e" : "Parallels Plesk",
  "6f767458b952d4755a795af0e4e0aa17" : "Yahoo!",
  "5b0e3b33aa166c88cee57f83de1d4e55" : "DotNetNuke (http",
  "7dbe9acc2ab6e64d59fa67637b1239df" : "Lotus-Domino",
  "fa54dbf2f61bd2e0188e47f5f578f736" : "Wordpress",
  "6cec5a9c106d45e458fc680f70df91b0" : "Wordpress - obsolete version",
  "81ed5fa6453cf406d1d82233ba355b9a" : "E-zekiel",
  "ecaa88f7fa0bf610a5a26cf545dcd3aa" : "3-byte invalid favicon",
  "c1201c47c81081c7f0930503cae7f71a" : "vBulletin forum",
  "edaaef7bbd3072a3a0c3fb3b29900bcb" : "Powered by Reynolds Web Solutions (Car sales CMS)",
  "d99217782f41e71bcaa8e663e6302473" : "Apache on Red Hat/Fedora",
  "a8fe5b8ae2c445a33ac41b33ccc9a120" : "Arris Touchstone Device",
  "d16a0da12074dae41980a6918d33f031" : "ST 605",
  "befcded36aec1e59ea624582fcb3225c" : "SpeedTouch",
  "e4a509e78afca846cd0e6c0672797de5" : "i3micro VRG",
  "3541a8ed03d7a4911679009961a82675" : "status.net",
  "fa2b274fab800af436ee688e97da4ac4" : "Etherpad",
  "83245b21512cc0a0e7a67c72c3a3f501" : "OpenXPKI",
  "85138f44d577b03dfc738d3f27e04992" : "Gitweb",
  "70625a6e60529a85cc51ad7da2d5580d" : "SSLstrip",
  "99306a52c76e19e3c298a46616c5899c" : "aMule (2.2.2)",
  "31c16dd034e6985b4ba929e251200580" : "Stephen Turner Analog (6.0)",
  "2d4cca83cf14d1adae178ad013bdf65b" : "Ant docs manual (1.7.1)",
  "032ecc47c22a91e7f3f1d28a45d7f7bc" : "Ant docs (1.7.1) / libjakarta-poi-java (3.0.2)",
  "31aa07fe236ee504c890a61d1f7f0a97" : "apache2 (2.2.9) docs-manual",
  "c0c4e7c0ac4da24ab8fc842d7f96723c" : "xsp (1.9.1)",
  "d6923071afcee9cebcebc785da40b226" : "autopsy (2.08)",
  "7513f4cf4802f546518f26ab5cfa1cad" : "axyl (2.6.0)",
  "de68f0ad7b37001b8241bce3887593c7" : "b2evolution (2.4.2)",
  "140e3eb3e173bfb8d15778a578a213aa" : "bmpx (0.40.14)",
  "4f12cccd3c42a4a478f067337fe92794" : "cacti (0.8.7b)",
  "c0533ae5d0ed638ba3fb3485d8250a28" : "CakePHP (1.1.x)",
  "66b3119d379aee26ba668fef49188dd3" : "cakephp (1.2.x-1.3x)",
  "09f5ea65a2d31da8976b9b9fd2bf853c" : "caudium (1.4.12)",
  "f276b19aabcb4ae8cda4d22625c6735f" : "cgiirc (0.5.9)",
  "a18421fbf34123c03fb8b3082e9d33c8" : "chora2 (2.0.2)",
  "23426658f03969934b758b7eb9e8f602" : "chronicle (2.9) theme-steve",
  "75069c2c6701b2be250c05ec494b1b31" : "chronicle (2.9) theme-blog.mail-scanning.com",
  "27c3b07523efd6c318a201cac58008ba" : "cimg (1.2.0.1)",
  "ae59960e866e2730e99799ac034eacf7" : "webcit (7.37)",
  "2ab2aae806e8393b70970b2eaace82e0" : "couchdb (0.8.0-0.9.1)",
  "ddd76f1cfe31499ce3db6702991cbc45" : "cream (0.41)",
  "74120b5bbc7be340887466ff6cfe66c6" : "cups (1.3.9) - doc",
  "abeea75cf3c1bac42bbd0e96803c72b9" : "doc-iana-20080601",
  "3ef81fad2a3deaeb19f02c9cf67ed8eb" : "dokuwiki (0.0.20080505)",
  "e6a9dc66179d8c9f34288b16a02f987e" : "Drupal CMS (5.10)",
  "bba9f1c29f100d265865626541b20a50" : "dtc (0.28.10)",
  "171429057ae2d6ad68e2cd6dcfd4adc1" : "ebug-http (0.31)",
  "f6e9339e652b8655d4e26f3e947cf212" : "eGroupWare (1.0.0.009, 1.4.004-2) (/phpgwapi/templates/idots/images/favicon.ico)",
  "093551287f13e0ee3805fee23c6f0e12" : "freevo (1.8.1)",
  "56753c5386a70edba6190d49252f00bb" : "gallery (1.5.8)",
  "54b299f2f1c8b56c8c495f2ded6e3e0b" : "garlic-doc (1.6)",
  "857281e82ea34abbb79b9b9c752e33d2" : "gforge (4.6.99+svn6496) - webcalendar",
  "27a097ec0dbffb7db436384635d50415" : "gforge (4.6.99+svn6496) - images",
  "0e14c2f52b93613b5d1527802523b23f" : "gforge (4.6.99+svn6496)",
  "c9339a2ecde0980f40ba22c2d237b94b" : "glpi (0.70.2)",
  "db1e3fe4a9ba1be201e913f9a401d794" : "gollem (1.0.3)",
  "921042508f011ae477d5d91b2a90d03f" : "gonzui (1.2+cvs20070129)",
  "ecab73f909ddd28e482ababe810447c8" : "gosa (2.5.16.1)",
  "c16b0a5c9eb3bfd831349739d89704ec" : "gramps (3.0.1)",
  "63d5627fc659adfdd5b902ecafe9100f" : "gsoap (2.7.9l)",
  "462794b1165c44409861fcad7e185631" : "hercules (3.05)",
  "3995c585b76bd5aa67cb6385431d378a" : "horde-sam (0.1+cvs20080316) - silver",
  "ee3d6a9227e27a5bc72db3184dab8303" : "horde-sam (0.1+cvs20080316) - graphics",
  "7cc1a052c86cc3d487957f7092a6d8c3" : "horde (3.2.1) - graphics/tango",
  "5e99522b02f6ecadbb3665202357d775" : "hplip (2.8.7) - installer",
  "39308a30527336e59d1d166d48c7742c" : "Hewlett-Packard HPLIP (2.8.7) - doc",
  "43d4aa56dc796067b442c95976a864fd" : "hunchentoot (0.15.7)",
  "32bf63ac2d3cfe82425ce8836c9ce87c" : "ikiwiki (2.56ubuntu1)",
  "f567fd4927f9693a7a2d6cacf21b51b6" : "Horde IMP (4.1.4 - 4.1.6, also used in Horde Groupware Webmail 1.0.1))",
  "919e132a62ea07fce13881470ba70293" : "Horde Groupware Webmail 1.0.1 (Ingo Theme, 1.1.5)",
  "ed7d5c39c69262f4ba95418d4f909b10" : "jetty (5.1.14)",
  "6900fab05a50a99d284405f46e5bc7f6" : "k3d (0.6.7.0)",
  "24d1e355c00e79dc13b84d5455534fe7" : "kdelibs (3.5.10-4.1.4)",
  "8ab2f1a55bcb0cac227828afd5927d39" : "kdenetwork (4.1.4)",
  "54667bea91124121e98da49e55244935" : "kolab-webadmin (2.1.0-20070510)",
  "a5b126cdeaa3081f77a22b3e43730942" : "Horde Groupware Webmail 1.0.1 (Kronolith Theme, 2.1.8)",
  "d00d85c8fb3a11170c1280c454398d51" : "ktorrent (3.1.2)",
  "fa21ab1b1e1b4c9516afbd63e91275a9" : "lastfmproxy (1.3b)",
  "663ee93a41000b8959d6145f0603f599" : "ldap-account-manager (2.3.0)",
  "ea84a69cb146a947fac2ac7af3946297" : "boost (1.34.1)",
  "eb3e307f44581916d9f1197df2fc9de3" : "flac (1.2.1)",
  "669bc10baf11b43391294aac3e1b8c52" : "libitpp (4.0.4)",
  "b8fe2ec1fcc0477c0d0f00084d824071" : "lucene (2.3.2)",
  "12225e325909cee70c31f5a7ab2ee194" : "ramaze-ruby (0.3.9.1)",
  "6be5ebd07e37d0b415ec83396a077312" : "ramaze-ruby (0.3.9.1) - dispatcher",
  "20e208bb83f3eeed7c1aa8a6d9d3229d" : "libswarmcache-java (1.0RC2+cvs20071027)",
  "5f8b52715c08dfc7826dad181c71dec8" : "mahara (1.0.4)",
  "ebe293e1746858d2548bca99c43e4969" : "Mantis Bug Tracker (1.1.2, /bugs/images/favicon.ico)",
  "0d42576d625920bcd121261fc5a6230b" : "mathomatic (14.0.6)",
  "f972c37bf444fb1925a2c97812e2c1eb" : "mediatomb (0.11.0)",
  "f5f2df7eec0d1c3c10b58960f3f8fb26" : "Horde Groupware Webmail 1.0.1 (Mnemo Theme, 2.1.2)",
  "933a83c6e9e47bd1e38424f3789d121d" : "Moodle (1.8.2, 1.9.x, multiple default themes)",
  "b6652d5d71f6f04a88a8443a8821510f" : "Moodle (1.8.2, 1.9.x, Cornflower Theme, /theme/cornflower/favicon.ico)",
  "06b60d90ccfb79c2574c7fdc3ac23f05" : "movabletype-opensource (4.2~rc4)",
  "21d80d9730a56b26dc9d252ffabb2987" : "mythplugins (0.21.0+fixes18722)",
  "81df3601d6dc13cbc6bd8212ef50dd29" : "Horde Groupware Webmail 1.0.1 (Nag Theme, 2.1.4)",
  "1c4201c7da53d6c7e48251d3a9680449" : "nagios (3.0.2)",
  "28015fcdf84ca0d7d382394a82396927" : "nanoblogger (3.3)",
  "868e7b460bba6fe29a37aa0ceff851ba" : "netmrg (0.20)",
  "0b2481ebc335a2d70fcf0cba0b3ce0fc" : "ntop (3.3)",
  "c30bf7e6d4afe1f02969e0f523d7a251" : "nulog (2.0)",
  "9a8035769d7a129b19feb275a33dc5b4" : "ocsinventory-server (1.01)",
  "75aeda7adbd012fa93c4ae80336b4f45" : "parrot (0.4.13) - docs",
  "70777a39f5d1de6d3873ffb309df35dd" : "pathological (1.1.3)",
  "82d746eb54b78b5449fbd583fc046ab2" : "perl-doc-html (5.10.0)",
  "90c244c893a963e3bb193d6043a347bd" : "phpgroupware (0.9.16.012)",
  "4b30eec86e9910e663b5a9209e9593b6" : "phpldapadmin (1.1.0.5)",
  "02dd7453848213a7b5277556bcc46307" : "phpmyadmin (2.11.8.1) - pmd",
  "d037ef2f629a22ddadcf438e6be7a325" : "phpmyadmin (2.11.8.1)",
  "8190ead2eb45952151ab5065d0e56381" : "pootle (1.1.0)",
  "ba84999dfc070065f37a082ab0e36017" : "prewikka (0.9.14)",
  "0f45c2c79ebe90d6491ddb111e810a56" : "python-cherrypy (2.3.0-3.0.2)",
  "e551b7017a9bd490fc5b76e833d689bf" : "MoinMoin (1.7.1)",
  "275e2e37fc7be50c1f03661ef8b6ce4f" : "myghty (1.1)",
  "68b329da9893e34099c7d8ad5cb9c940" : "myghty (1.1) - zblog",
  "5488c1c8bf5a2264b8d4c8541e2d5ccd" : "turbogears (1.0.4.4) - genshi/elixir",
  "6927da350550f29bc641138825dff36f" : "python-werkzeug (0.3.1) - docs",
  "e3f28aab904e9edfd015f64dc93d487d" : "python-werkzeug (0.3.1) - cupoftee-examples",
  "69f8a727f01a7e9b90a258bc30aaae6a" : "quantlib-refman-html (0.9.0)",
  "b01625f4aa4cd64a180e46ef78f34877" : "quickplot (0.8.13)",
  "af83bba99d82ea47ca9dafc8341ec110" : "qwik (0.8.4.4ubuntu2)",
  "e9469705a8ac323e403d74c11425a62b" : "roundcube (0.1.1)",
  "7f57bbd0956976e797b4e8eebdc6d733" : "selfhtml (8.1.1)",
  "69acfcb2659952bc37c54108d52fca70" : "solr (1.2.0) - docs",
  "ffc05799dee87a4f8901c458f7291d73" : "solr (1.2.0) - admin",
  "aa2253a32823c8a5cba8d479fecedd3a" : "sork-forwards-h3 (3.0.1)",
  "a2e38a3b0cdf875cd79017dcaf4f2b55" : "sork-passwd-h3 (3.0)",
  "cb740847c45ea3fbbd80308b9aa4530a" : "sork-vacation-h3 (3.0.1)",
  "7c7b66d305e9377fa1fce9f9a74464d9" : "spe (0.8.4.h)",
  "0e2503a23068aac350f16143d30a1273" : "sql-ledger (2.8.15)",
  "1fd3fafc1d461a3d19e91dbbba03d0aa" : "tea (17.6.1)",
  "4644f2d45601037b8423d45e13194c93" : "Apache Tomcat (5.5.26), Alfresco Community",
  "1de863a5023e7e73f050a496e6b104ab" : "torrentflux (2.4)",
  "83dea3d5d8c6feddec84884522b61850" : "torrentflux (2.4) - themes/G4E/",
  "d1bc9681dce4ad805c17bd1f0f5cee97" : "torrentflux (2.4) - themes/BlueFlux/",
  "8d13927efb22bbe7237fa64e858bb523" : "transmission (1.34)",
  "5b015106854dc7be448c14b64867dfa5" : "tulip (3.0.0~B6)",
  "ff260e80f5f9ca4b779fbd34087f13cf" : "Horde Groupware Webmail 1.0.1 (Turba Theme, 2.1.7)",
  "e7fc436d0bf31500ced7a7143067c337" : "twiki (4.1.2) - logos/favicon.ico",
  "9789c9ab400ea0b9ca8fcbd9952133bd" : "twiki (4.1.2) - webpreferences",
  "2b52c1344164d29dd8fb758db16aadb6" : "vdr-plugin-live (0.2.0)",
  "237f837bbc33cd98a9f47b20b284e2ad" : "vdradmin-am (3.6.1)",
  "6f7e92fe7e6a62661ac2b41528a78fc6" : "vlc (0.9.4)",
  "2507c0b0a60ecdc816ba45482affaedf" : "webcheck (1.10.2.0)",
  "ef5169b040925a716359d131afbea033" : "websvn (2.0)",
  "f6d0a100b6dbeb5899f0975a1203fd85" : "witty (2.1.5)",
  "81feac35654318fb16d1a567b8b941e7" : "yaws (1.77)",
  "33b04fb9f2ec918f5f14b41527e77f6d" : "znc (0.058)",
  "6434232d43f27ef5462ba5ba345e03df" : "znc (0.058, webadmin/skins/default)",
  "e07c0775523271d629035dc8921dffc7" : "zoneminder (1.23.3)",
  "4eb846f1286ab4e7a399c851d7d84cca" : "Plone CMS (3.1.1)",
  "e298e00b2ff6340343ddf2fc6212010b" : "Nessus 4.x Scanner Web Client",
  "240c36cd118aa1ff59986066f21015d4" : "LANCOM Systems",
  "ceb25c12c147093dc93ac8b2c18bebff" : "COMpact 5020 VoIP",
  "05656826682ab3147092991ef5de9ef3" : "RapidShare",
  "e19ffb2bc890f5bdca20f10bfddb288d" : "Rapid7 (NeXpose)",
  "1f8c0b08fb6b556a6587517a8d5f290b" : "owasp.org",
  "73778a17b0d22ffbb7d6c445a7947b92" : "Apache on Mac OS X",
  "799f70b71314a7508326d1d2f68f7519" : "JBoss Server",
  "bd0f7466d35e8ba6cedd9c27110c5c41" : "Serena Collage (4.6, servlet/images/collage_app.ico)",
  "dc0816f371699823e1e03e0078622d75" : "Aruba Network Devices (HTTP(S) login page)",
  "f097f0adf2b9e95a972d21e5e5ab746d" : "Citrix Access Server",
  "28893699241094742c3c2d4196cd1acb" : "Xerox DocuShare",
  "80656aabfafe0f3559f71bb0524c4bb3" : "Macromedia Breeze",
  "48c02490ba335a159b99343b00decd87" : "Octeth Technologies oemPro (3.5.5.1)",
  "eb6d4ce00ec36af7d439ebd4e5a395d7" : "Mailman",
  "04d89d5b7a290334f5ce37c7e8b6a349" : "Atlassian Jira Bug Tracker",
  "d80e364c0d3138c7ecd75bf9896f2cad" : "Apache Tomcat (6.0.18), Alfresco Enterprise Content Management System",
  "a6b55b93bc01a6df076483b69039ba9c" : "Fog Creek Fogbugz (6.1.44)",
  "ee4a637a1257b2430649d6750cda6eba" : "Trimble Device Embedded Web Server",
  "9ceae7a3c88fc451d59e24d8d5f6f166" : "Plesk managed system",
  "69ae01d0c74570d4d221e6c24a06d73b" : "Roku Soundbridge",
  "2e9545474ee33884b5fb8a9a0b8806dd" : "Ampache",
  "639b61409215d770a99667b446c80ea1" : "Lotus Domino Server",
  "be6fb62815509bd707e69ee8dad874a1" : "i.LON server by Echelon",
  "a46bc7fc42979e9b343335bdd86d1c3e" : "NetScout NGenius",
  "192decdad41179599a776494efc3e720" : "JBoss Installation",
  "de2b6edbf7930f5dd0ffe0528b2bbcf4" : "Barracuda Spam/Virus firewall appliance",
  "386211e5c0b7d92efabd41390e0fc250" : "SparkWeb web-based collaboration client. http",
  "f89abd3f358cb964d6b753a5a9da49cf" : "LimeSurvey",
  "a7947b1675701f2247921cf4c2b99a78" : "Alexander Palmo Simple PHP Blog",
  "01febf7c2bd75cd15dae3aa093d80552" : "Atlassian Crucible or Fisheye",
  "1275afc920a53a9679d2d0e8a5c74054" : "Atlassian Crowd",
  "12888a39a499eb041ca42bf456aca285" : "Atlassian Confluence or Crowd",
  "3341c6d3c67ccdaeb7289180c741a965" : "Atlassian Confluence or Crowd",
  "6c1452e18a09070c0b3ed85ce7cb3917" : "Atlassian Jira",
  "43ba066789e749f9ef591dc086f3cd14" : "Atlassian Bamboo",
  "a83dfece1c0e9e3469588f418e1e4942" : "Atlassian Bamboo",
  "f0ee98b4394dfdab17c16245dd799204" : "Drupal",
  "7b0d4bc0ca1659d54469e5013a08d240" : "Netgear (Infrant) ReadyNAS NV+",
  "cee40c0b35bded5e11545be22a40e363" : "OSSDL.de Openmailadmin",
  "4f88ba9f1298701251180e6b6467d43e" : "Xinit Systems Ltd. Openfiler",
  "4c3373870496151fd02a6f1185b0bb68" : "rPath Appliance Agent",
  "b231ad66a2a9b0eb06f72c4c88973039" : "Wordpress",
  "e1e8bdc3ce87340ab6ebe467519cf245" : "Wordpress",
  "95103d0eabcd541527a86f23b636e794" : "Wordpress Multi-User (MU)",
  "64ca706a50715e421b6c2fa0b32ed7ec" : "Parallels Plesk Control Panel",
  "f425342764f8c356479d05daa7013c2f" : "vBulletin forum",
  "740af61c776a3cb98da3715bdf9d3fc1" : "vBulletin forum",
  "d7ac014e83b5c4a2dea76c50eaeda662" : "vBulletin forum",
  "a47951fb41640e7a2f5862c296e6f218" : "Plone CMS",
  "10bd6ad7b318df92d9e9bd03104d9b80" : "Plone CMS",
  "e08333841cbe40d15b18f49045f26614" : "21publish Blog",
  "e2cac3fad9fa3388f639546f3ba09bc0" : "Invision Power Services IP.Board",
  "5ec8d0ecf7b505bb04ab3ac81535e062" : "Telligent Community Server",
  "83a1fd57a1e1684fafd6d2487290fdf5" : "Pligg",
  "b7f98dd27febe36b7275f22ad73c5e84" : "MoinMoin",
  "63b982eddd64d44233baa25066db6bc1" : "Joomla!",
  "05bc6d56d8df6d668cf7e9e11319f4e6" : "Jive Forums",
  "63740175dae089e479a70c5e6591946c" : "The Lyceum Project",
  "4cbb2cfc30a089b29cd06179f9cc82ff" : "Dragonfly",
  "9187f6607b402df8bbc2aeb69a07bbca" : "XOOPS",
  "a1c686eb6e771878cf6040574a175933" : "CivicPlus",
  "4d7fe200d85000aea4d193a10e550d04" : "Intland Software codeBeamer",
  "1a9a1ec2b8817a2f951c9f1793c9bc54" : "Bitweaver",
  "1cc16c64d0e471607677b036b3f06b6e" : "Roller Weblogger Project",
  "7563f8c3ebd4fd4925f61df7d5ed8129" : "Holger Zimmerman Pi3Web HTTP Server",
  "7f0f918a78ca8d4d5ff21ea84f2bac68" : "SubText",
  "86e3bf076a018a23c12354e512af3b9c" : "Spyce",
  "9c003f40e63df95a2b844c6b61448310" : "DD-WRT Embedded Web Server",
  "9a9ee243bc8d08dac4448a5177882ea9" : "Dvbbs Forum",
  "ee1169dee71a0a53c91f5065295004b7" : "ProjectPier",
  "7214637a176079a335d7ac529011f4e4" : "phpress",
  "1bf954ba2d568ec9771d35c94a6eb2dc" : "WoltLab Burning Board",
  "ff3b533b061cee7cfbca693cc362c34a" : "Kayako SupportSuite",
  "428b23df874b41d904bbae29057bdba5" : "Comsenz Technology Ltd ECShop",
  "8757fcbdbd83b0808955f6735078a287" : "Comsenz Technology Ltd Discuz!",
  "9fac8b45400f794e0799d0d5458c092b" : "Comsenz Technology Ltd Discuz!",
  "4e370f295b96eef85449c357aad90328" : "Comsenz Technology Ltd SupeSite",
  "4cfbb29d0d83685ba99323bc0d4d3513" : "PHPWind Forums 7",
  "2df6edffca360b7a0fadc3bdf2191857" : "PIPS Technology ATZ Executive / Automatic Licence Plate Recognition (ALPR) System",
  "8c291e32e7c7c65124d19eb17bceca87" : "Schneider Electric Modicon 340 / BMX P34 CPU B",
  "6dcab71e60f0242907940f0fcda69ea5" : "Ubiquiti Ubiquiti M Series / AirOS",
  "09a1e50dc3369e031b97f38abddd10c8" : "Ubiquiti Ubiquiti M Series / AirOS",
  "7b345857204926b62951670cd17a08b7" : "AXESS TMC X1 or X2 Terminal",
  "28c34462a074c5311492759435549468" : "AContent x",
  "705d63d8f6f485bd40528394722b5c22" : "Atmail x",
  "9f500a24ccbdda88cf8ae3ec7b61fc40" : "Atomic CMS x",
  "5b816961f19da96ed5a2bf15e79093cb" : "ATutor x",
  "f51425ace97f807fe5840c4382580fd5" : "Beehive Forum 1.x",
  "eb05f77bf80d66f0db6b1f682ff08bee" : "Biscom Delivery Server x",
  "5d27143fc38439baba39ba5615cbe9ef" : "Cascade Server x",
  "0c53ef3d151cbac70a8486dd1ebc8b25" : "Chamilo e-learning system x",
  "9939a032a9845e4d931d14e08f5a6c7c" : "Citrix XenApp Logon",
  "6c633b9b92530843c782664cb3f0542d" : "ClipBucket x",
  "a59c6fead5d55050674f327955df3acb" : "CouchPotato 2.x",
  "107579220745d3b21461c23024d6c4a3" : "D-Link x",
  "c86974467c2ac7b6902189944f812b9a" : "Domain Technology Control 0.17.x-0.24.x",
  "d9aa63661d742d5f7c7300d02ac18d69" : "Dreambox WebControl x",
  "a4819787db1dabe1a6b669d5d6df3bfd" : "Drupal 2.x-4.x",
  "b6341dfc213100c61db4fb8775878cec" : "Drupal 7.x",
  "0a99a23f6b1f1bddb94d2a2212598628" : "Maraschino x",
  "51b916bdaf994ce73d3e5e6dfe2a46ee" : "Feng Office 2.3",
  "d134378a39c722e941ac25eed91ca93b" : "FreePBX x",
  "45210ace96ce9c893f8c27c5decab10d" : "Fritz! x",
  "835306119474fefb6b38ae314a37943a" : "Horde Agora (Forum) x",
  "b64a1155b80e0b06272f8b842b83fa57" : "Horde Ansel (Photo Manager) x",
  "0e6a6ed665a9669b368d9a90b87976a9" : "Horde Gollem (File Manager) x",
  "6c18a6e983f64b6a6ed0a32c9e8a19b6" : "HP ProCurve Webserver x",
  "6acfee4c670580ebf06edae40631b946" : "Iomega StorCenter x",
  "1f9c39ef3f740eebb046c900edac4ba5" : "Iomega StorCenter ix2-200 x",
  "37a99d2ddea8b49f701db457b9a8ffed" : "Iomega StorCenter ix4-200d x",
  "e7dce6ac6d8713a0b98407254ca33f80" : "Iomega StorCenter ix4-300d x",
  "f08d232927ab8f2c661616b896928233" : "Iomega StorCenter px2-300d x",
  "9d203fbb74eabf67f48b965ba5acc9a6" : "Iomega StorCenter px4-300d x",
  "fbd140da4eff02b90c9ebcbdb3736322" : "Iomega StorCenter px4-300r x",
  "fd3f689b804ddb7bfab53fdf32bf7c04" : "Iomega StorCenter px6-300d x",
  "8dfab2d881ce47dc41459c6c0c652bcf" : "Iomega StorCenter px12-350r x",
  "66dcdd811a7d8b1c7cd4e15cef9d4406" : "Iomega StorCenter px12-400r x",
  "a7fe149a9f2582f38576d14d9b1f0f55" : "LaCie Dashboard x",
  "2ba9b777483da0a6a8b29c4ab39a10b2" : "MagicMail x",
  "701bb703b31f99da18251ca2e557edf0" : "Mantis Bug Tracker 1.2.9-1.2.15",
  "d4af3be33d952c1f98684d985019757c" : "Moodle 2.0 : Magazine",
  "b88c0eedc72d3bf4e86c2aa0a6ba6f7b" : "NAS4Free 9.0",
  "11abb4301d06dccc36d1b5f6dcad093e" : "ntop 3.3.6-5.0.1",
  "b9d28bd6822d2e09e01aa0af5d7ccc34" : "ocPortal 9.0.5",
  "eec3051d5c356d1798bea1d8a3617c51" : "Octopress x",
  "9c34a7481ba0c153bb3e2a10e0ea811e" : "OpenWebif x",
  "49bf194d1eccb1e5110957d14559d33d" : "OTRS x",
  "d361075db94bb892ff3fb3717714b2da" : "phpMyBackupPro x",
  "a456dd2bae5746beb68814a5ac977048" : "phpSysInfo 3.0.7",
  "6e0c5b7979e9950125c71341e0960f65" : "phpSysInfo 3.0.8-3.0.12",
  "ddcc65196f0bc63a90c885bd88ecbb81" : "phpSysInfo 3.0.12-3.0.20, 3.1.0-3.1.4",
  "ba4bfe5d1deb2b4410e9eb97c5b74c9b" : "Puppet Node Manager x",
  "368c15ac73f0096aa3daff8ff6f719f8" : "Redaxscript 1.0-1.2.1",
  "6d85758acb4f4baa4d242ba451c91026" : "Redmine x, Request Tracker x",
  "228ba3f6d946af4298b080e5c934487c" : "Roundcube Webmail 0.6-0.7 : Default, 0.8-0.9 : Classic, 0.8-0.9 : Larry",
  "ed8cf53ef6836184587ee3a987be074a" : "Ruckus x",
  "f6c5f5e8857ecf561029fc5da005b6e3" : "Sophos Email Appliance x",
  "f682dbd4d0a18dd7699339b8adb28c0f" : "QNAP TurboNAS 3.8.x : Admin",
  "7ff45523a7ee9686d3d391a0a27a0b4f" : "QNAP TurboNAS 4.0.x",
  "a967c8bfde9ea0869637294b679b7251" : "Squid Proxy Server x",
  "bc18566dcc41a0ff503968f461c4995a" : "Subrion CMS x",
  "531e652a15bc0ad59b6af05019b1834a" : "Synology DSM 4.2",
  "0ec12e5820517d3b62e56b9a8f1ee5bc" : "TradingEye x",
  "300b5c3f134d7ec0bca862cf113149d8" : "TVersity x",
  "8718c2998236c796896b725f264092ee" : "Typo3 6.1",
  "7350c3f75cb80e857efa88c2fd136da5" : "Ushahidi x",
  "2e5e985fe125e3f8fca988a86689b127" : "VISEC x",
  "d90cc1762bf724db71d6df86effab63c" : "vtiger CRM x",
  "b14353fafda7c90fb1a2a214c195de50" : "webERP x",
  "18fe76b96d4eae173bf439a9712fa5c1" : "WikiWebHelp x",
  "e44d22b74f7ee4435e22062d5adf4a6a" : "WordPress 2.x",
  "3ead5afa19537170bb980924397b70d6" : "WordPress 3.x : Twenty Ten",
  "28a122aa74f6929b0994fc544555c0b1" : "WordPress 3.2-3.x : Twenty Eleven",
  "e9dd9992d222d67c8f6a4704d2c88bdd" : "Zarafa WebAccess x",
  "c126f7e761813946fea2e90ff7ddb838" : "Zenoss Core x",
  "5a77e47fa23554a4166d2303580b0733" : "Sawmill",
  "a4eb4e0aa80740db8d7d951b6d63b2a2" : "ownCloud",
  "531b63a51234bb06c9d77f219eb25553" : "phpmyadmin (4.6.x)",
  "ef9c0362bf20a086bb7c2e8ea346b9f0" : "Roundcube Webmail 1.0.0+, Skins Classic and Larry",
  "f1ac749564d5ba793550ec6bdc472e7c" : "Roundcube Webmail 1.4.0+, Elastic Skin",
  "23e8c7bd78e8cd826c5a6073b15068b1" : "Jenkins",
  "57f501d6fee2fdb024795abbdb750ad5" : "Hak5 Cloud C2",
  "297a81069094d00a052733d3a0537d18" : "CrushFTP",
  "f3418a443e7d841097c714d69ec4bcb8" : "Google"
}

FINGERPRINTS =  {
            9395752:"slack-instanc",
            116323821:"spring-boot",
            81586312:"Jenkins",
            -235701012:"Cnservers LC",
            743365239:"Atlassian",
            2128230701:"Chainpoint",
            -1277814690:"LaCie",
            246145559:"Parse",
            628535358:"Atlassian",
            855273746:"JIRA",
            1318124267:"Avigilon",
            -305179312:"Atlassian – Confluence",
            786533217:"OpenStack",
            432733105:"Pi Star",
            705143395:"Atlassian",
            -1255347784:"Angular IO (AngularJS)",
            -1275226814:"XAMPP",
            -2009722838:"React",
            981867722:"Atlassian – JIRA",
            -923088984:"OpenStack",
            494866796:"Aplikasi",
            2110041688:"ระบบจองห้องประชุม",
            -493051473:"hxxp://www[.k2ie.net",
            1249285083:"Ubiquiti Aircube",
            -1379982221:"Atlassian – Bamboo",
            420473080:"Exostar – Managed Access Gateway",
            -1642532491:"Atlassian – Confluence",
            163842882:"Cisco Meraki",
            -1378182799:"Archivematica",
            -702384832:"TCN",
            -532394952:"CX",
            -183163807:"Ace",
            552727997:"Atlassian – JIRA",
            1302486561:"NetData",
            -609520537:"OpenGeo Suite",
            -1961046099:"Dgraph Ratel",
            -1581907337:"Atlassian – JIRA",
            1913538826:"Material Dashboard",
            1319699698:"Form.io",
            -1203021870:"Kubeflow",
            -182423204:"netdata dashboard",
            988422585:"CapRover",
            2113497004:"WiJungle",
            1234311970:"Onera",
            430582574:"SmartPing",
            1232596212:"OpenStack",
            1585145626:"netdata dashboard",
            -219752612:"FRITZ!Box",
            -697231354:"Ubiquiti – AirOS",
            945408572:"Fortinet – Forticlient",
            1768726119:"Outlook Web Application",
            2109473187:"Huawei – Claro",
            552592949:"ASUS AiCloud",
            631108382:"SonicWALL",
            708578229:"Google",
            -134375033:"Plesk",
            2019488876:"Dahua Storm (IP Camera)",
            -1395400951:"Huawei – ADSL/Router",
            1601194732:"Sophos Cyberoam (appliance)",
            -325082670:"LANCOM Systems",
            -1050786453:"Plesk",
            -1346447358:"TilginAB (HomeGateway)",
            1410610129:"Supermicro Intelligent Management (IPMI)",
            -440644339:"Zyxel ZyWALL",
            363324987:"Dell SonicWALL",
            -1446794564:"Ubiquiti Login Portals",
            1045696447:"Sophos User Portal/VPN Portal",
            -297069493:"Apache Tomcat",
            396533629:"OpenVPN",
            1462981117:"Cyberoam",
            1772087922:"ASP.net favicon",
            1594377337:"Technicolor",
            165976831:"Vodafone (Technicolor)",
            -1677255344:"UBNT Router UI",
            -359621743:"Intelbras Wireless",
            -677167908:"Kerio Connect (Webmail)",
            878647854:"BIG-IP",
            442749392:"Microsoft OWA",
            1405460984:"pfSense",
            -271448102:"iKuai Networks",
            31972968:"Dlink Webcam",
            970132176:"3CX Phone System",
            -1119613926:"Bluehost",
            123821839:"Sangfor",
            459900502:"ZTE Corporation (Gateway/Appliance)",
            -2069844696:"Ruckus Wireless",
            -1607644090:"Bitnami",
            2141724739:"Juniper Device Manager",
            1835479497:"Technicolor Gateway",
            1278323681:"Gitlab",
            -1929912510:"NETASQ - Secure / Stormshield",
            -1255992602:"VMware Horizon",
            1895360511:"VMware Horizon",
            -991123252:"VMware Horizon",
            1642701741:"Vmware Secure File Transfer",
            -266008933:"SAP Netweaver",
            -1967743928:"SAP ID Service: Log On",
            1347937389:"SAP Conversational AI",
            602431586:"Palo Alto Login Portal",
            -318947884:"Palo Alto Networks",
            1356662359:"Outlook Web Application",
            1453890729:"Webmin",
            -1814887000:"Docker",
            1937209448:"Docker",
            -1544605732:"Amazon",
            716989053:"Amazon",
            -1010568750:"phpMyAdmin",
            -1240222446:"Zhejiang Uniview Technologies Co.",
            -986678507:"ISP Manager",
            -1616143106:"AXIS (network cameras)",
            -976235259:"Roundcube Webmail",
            768816037:"UniFi Video Controller (airVision)",
            1015545776:"pfSense",
            1838417872:"Freebox OS",
            1188645141:"hxxps://www.hws[.com/?host",
            547282364:"Keenetic",
            -1571472432:"Sierra Wireless Ace Manager (Airlink)",
            149371702:"Synology DiskStation",
            -1169314298:"INSTAR IP Cameras",
            -1038557304:"Webmin",
            1307375944:"Octoprint (3D printer)",
            1280907310:"Webmin",
            1954835352:"Vesta Hosting Control Panel",
            509789953:"Farming Simulator Dedicated Server",
            -1933493443:"Residential Gateway",
            1993518473:"cPanel Login",
            -1477563858:"Arris",
            -895890586:"PLEX Server",
            -1354933624:"Dlink Webcam",
            944969688:"Deluge",
            479413330:"Webmin",
            -359621743:"Intelbras Wireless",
            -435817905:"Cambium Networks",
            -981606721:"Plesk",
            833190513:"Dahua Storm (IP Camera)",
            -1314864135:10,
            -652508439:"Parallels Plesk Panel",
            -569941107:"Fireware Watchguard",
            1326164945:"Shock&Innovation!! netis setup",
            -1738184811:"cacaoweb",
            904434662:"Loxone (Automation)",
            905744673:"HP Printer / Server",
            902521196:"Netflix",
            -2063036701:"Linksys Smart Wi-Fi",
            -1205024243:"lwIP (A Lightweight TCP/IP stack)",
            607846949:"Hitron Technologies",
            1281253102:"Dahua Storm (DVR)",
            661332347:"MOBOTIX Camera",
            -520888198:"Blue Iris (Webcam)",
            104189364:"Vigor Router",
            1227052603:"Alibaba Cloud (Block Page)",
            252728887:"DD WRT (DD-WRT milli_httpd)",
            -1922044295:"Mitel Networks (MiCollab End User Portal)",
            1221759509:"Dlink Webcam",
            1037387972:"Dlink Router",
            -655683626:"PRTG Network Monitor",
            1611729805:"Elastic (Database)",
            1144925962:"Dlink Webcam",
            -1666561833:"Wildfly",
            804949239:"Cisco Meraki Dashboard",
            -459291760:"Workday",
            1734609466:"JustHost",
            -1507567067:"Baidu (IP error page)",
            2006716043:"Intelbras SA",
            -1298108480:"Yii PHP Framework (Default Favicon)",
            1782271534:"truVision NVR (interlogix)",
            603314:"Redmine",
            -476231906:"phpMyAdmin",
            -646322113:"Cisco (eg:Conference Room Login Page)",
            -629047854:"Jetty 404",
            -1351901211:"Luma Surveillance",
            -519765377:"Parallels Plesk Panel",
            -2144363468:"HP Printer / Server",
            -127886975:"Metasploit",
            1139788073:"Metasploit",
            -1235192469:"Metasploit",
            1876585825:"ALIBI NVR",
            -1810847295:"Sangfor",
            -291579889:"Websockets test page (eg: port 5900)",
            1629518721:"macOS Server (Apple)",
            -986816620:"OpenRG",
            -299287097:"Cisco Router",
            -1926484046:"Sangfor",
            -873627015:"HeroSpeed Digital Technology Co. (NVR/IPC/XVR)",
            2071993228:"Nomadix Access Gateway",
            516963061:"Gitlab",
            -38580010:"Magento",
            1490343308:"MK-AUTH",
            -632583950:"Shoutcast Server",
            95271369:"FireEye",
            1476335317:"FireEye",
            -842192932:"FireEye",
            105083909:"FireEye",
            240606739:"FireEye",
            2121539357:"FireEye",
            -333791179:"Adobe Campaign Classic",
            -1437701105:"XAMPP",
            -676077969:"Niagara Web Server",
            -2138771289:"Technicolor",
            711742418:"Hitron Technologies Inc.",
            728788645:"IBM Notes",
            1436966696:"Barracuda",
            86919334:"ServiceNow",
            1211608009:"Openfire Admin Console",
            2059618623:"HP iLO",
            1975413433:"Sunny WebBox",
            943925975:"ZyXEL",
            281559989:"Huawei",
            -2145085239:"Tenda Web Master",
            -1399433489:"Prometheus Time Series Collection and Processing Server",
            1786752597:"wdCP cloud host management system",
            90680708:"Domoticz (Home Automation)",
            -1441956789:"Tableau",
            -675839242:"openWRT Luci",
            1020814938:"Ubiquiti – AirOS",
            -766957661:"MDaemon Webmail",
            119741608:"Teltonika",
            1973665246:"Entrolink",
            74935566:"WindRiver-WebServer",
            -1723752240:"Microhard Systems",
            -1807411396:"Skype",
            -1612496354:"Teltonika",
            1877797890:"Eltex (Router)",
            -375623619:"bintec elmeg",
            1483097076:"SyncThru Web Service (Printers)",
            1169183049:"BoaServer",
            1051648103:"Securepoint",
            -438482901:"Moodle",
            -1492966240:"RADIX",
            1466912879:"CradlePoint Technology (Router)",
            -167656799:"Drupal",
            -1593651747:"Blackboard",
            -895963602:"Jupyter Notebook",
            -972810761:"HostMonster - Web hosting",
            1703788174:"D-Link (router/network)",
            225632504:"Rocket Chat",
            -1702393021:"mofinetwork",
            892542951:"Zabbix",
            547474373:"TOTOLINK (network)",
            -374235895:"Ossia (Provision SR) | Webcam/IP Camera",
            1544230796:"cPanel Login",
            517158172:"D-Link (router/network)",
            462223993:"Jeedom (home automation)",
            937999361:"JBoss Application Server 7",
            1991562061:"Niagara Web Server / Tridium",
            812385209:"Solarwinds Serv-U FTP Server",
            1142227528:"Aruba (Virtual Controller)",
            -1153950306:"Dell",
            72005642:"RemObjects SDK / Remoting SDK for .NET HTTP Server Microsoft",
            -484708885:"Zyxel ZyWALL",
            706602230:"VisualSVN Server",
            -656811182:"Jboss",
            -332324409:"STARFACE VoIP Software",
            -594256627:"Netis (network devices)",
            -649378830:"WHM",
            97604680:"Tandberg",
            -1015932800:"Ghost (CMS)",
            -194439630:"Avtech IP Surveillance (Camera)",
            129457226:"Liferay Portal",
            -771764544:"Parallels Plesk Panel",
            -617743584:"Odoo",
            77044418:"Polycom",
            980692677:"Cake PHP",
            476213314:"Exacq",
            794809961:"CheckPoint",
            1157789622:"Ubiquiti UNMS",
            1244636413:"cPanel Login",
            1985721423:"WorldClient for Mdaemon",
            -1124868062:"Netport Software (DSL)",
            -335242539:"f5 Big IP",
            2146763496:"Mailcow",
            -1041180225:"QNAP NAS Virtualization Station",
            -1319025408:"Netgear",
            917966895:"Gogs",
            512590457:"Trendnet IP camera",
            1678170702:"Asustor",
            -1466785234:"Dahua",
            -505448917:"Discuz!",
            255892555:"wdCP cloud host management system",
            1627330242:"Joomla",
            -1935525788:"SmarterMail",
            -12700016:"Seafile",
            1770799630:"bintec elmeg",
            -137295400:"NETGEAR ReadyNAS",
            -195508437:"iPECS",
            -2116540786:"bet365",
            -38705358:"Reolink",
            -450254253:"idera",
            -1630354993:"Proofpoint",
            -1678298769:"Kerio Connect WebMail",
            -35107086:"WorldClient for Mdaemon",
            2055322029:"Realtek",
            -692947551:"Ruijie Networks (Login)",
            -1710631084:"Askey Cable Modem",
            89321398:"Askey Cable Modem",
            90066852:"JAWS Web Server (IP Camera)",
            768231242:"JAWS Web Server (IP Camera)",
            -421986013:"Homegrown Website Hosting",
            156312019:"Technicolor / Thomson Speedtouch (Network / ADSL)",
            -560297467:"DVR (Korean)",
            -1950415971:"Joomla",
            1842351293:"TP-LINK (Network Device)",
            1433417005:"Salesforce",
            -632070065:"Apache Haus",
            1103599349:"Untangle",
            224536051:"Shenzhen coship electronics co.",
            1038500535:"D-Link (router/network)",
            -355305208:"D-Link (camera)",
            -267431135:"Kibana",
            -759754862:"Kibana",
            -1200737715:"Kibana",
            75230260:"Kibana",
            1668183286:"Kibana",
            283740897:"Intelbras SA",
            1424295654:"Icecast Streaming Media Server",
            1922032523:"NEC WebPro",
            -1654229048:"Vivotek (Camera)",
            -1414475558:"Microsoft IIS",
            -1697334194:"Univention Portal",
            -1424036600:"Portainer (Docker Management)",
            -831826827:"NOS Router",
            -759108386:"Tongda",
            -1022206565:"CrushFTP",
            -1225484776:"Endian Firewall",
            -631002664:"Kerio Control Firewall",
            2072198544:"Ferozo Panel",
            -466504476:"Kerio Control Firewall",
            1251810433:"Cafe24 (Korea)",
            1273982002:"Mautic (Open Source Marketing Automation)",
            -978656757:"NETIASPOT (Network)",
            916642917:"Multilaser",
            575613323:"Canvas LMS (Learning Management)",
            1726027799:"IBM Server",
            -587741716:"ADB Broadband S.p.A. (Network)",
            -360566773:"ARRIS (Network)",
            -884776764:"Huawei (Network)",
            929825723:"WAMPSERVER",
            240136437:"Seagate Technology (NAS)",
            1911253822:"UPC Ceska Republica (Network)",
            -393788031:"Flussonic (Video Streaming)",
            366524387:"Joomla",
            443944613:"WAMPSERVER",
            1953726032:"Metabase",
            -2031183903:"D-Link (Network)",
            545827989:"MobileIron",
            967636089:"MobileIron",
            362091310:"MobileIron",
            2086228042:"MobileIron",
            -1588746893:"CommuniGate",
            1427976651:"ZTE (Network)",
            1648531157:"InfiNet Wireless | WANFleX (Network)",
            938616453:"Mersive Solstice",
            1632780968:"Université Toulouse 1 Capitole",
            2068154487:"Digium (Switchvox)",
            -1788112745:"PowerMTA monitoring",
            -644617577:"SmartLAN/G",
            -1822098181:"Checkpoint (Gaia)",
            -1131689409:"УТМ (Federal Service for Alcohol Market Regulation | Russia)",
            2127152956:"MailWizz",
            1064742722:"RabbitMQ",
            -693082538:"openmediavault (NAS)",
            1941381095:"openWRT Luci",
            903086190:"Honeywell",
            829321644:"BOMGAR Support Portal",
            -1442789563:"Nuxt JS",
            -2140379067:"RoundCube Webmail",
            -1897829998:"D-Link (camera)",
            1047213685:"Netgear (Network)",
            1485257654:"SonarQube",
            -299324825:"Lupus Electronics XT",
            -1162730477:"Vanderbilt SPC",
            -1268095485:"VZPP Plesk",
            1118684072:"Baidu",
            -1616115760:"ownCloud",
            -2054889066:"Sentora",
            1333537166:"Alfresco",
            -373674173:"Digital Keystone (DK)",
            -106646451:"WISPR (Airlan)",
            1235070469:"Synology VPN Plus",
            2063428236:"Sentry",
            15831193:"WatchGuard",
            -956471263:"Web Client Pro",
            -1452159623:"Tecvoz",
            99432374:"MDaemon Remote Administration",
            727253975:"Paradox IP Module",
            -630493013:"DokuWiki",
            552597979:"Sails",
            774252049:"FastPanel Hosting",
            -329747115:"C-Lodop",
            1262005940:"Jamf Pro Login",
            979634648:"StruxureWare (Schneider Electric)",
            475379699:"Axcient Replibit Management Server",
            -878891718:"Twonky Server (Media Streaming)",
            -2125083197:"Windows Azure",
            -1151675028:"ISP Manager (Web Hosting Panel)",
            1248917303:"JupyterHub",
            -1908556829:"CenturyLink Modem GUI Login (eg: Technicolor)",
            1059329877:"Tecvoz",
            -1148190371:"OPNsense",
            1467395679:"Ligowave (network)",
            -1528414776:"Rumpus",
            -2117390767:"Spiceworks (panel)",
            -1944119648:"TeamCity",
            -1748763891:"INSTAR Full-HD IP-Camera",
            251106693:"GPON Home Gateway",
            -1779611449:"Alienvault",
            -1745552996:"Arbor Networks",
            -1275148624:"Accrisoft",
            -178685903:"Yasni",
            -43161126:"Slack",
            671221099:"innovaphone",
            -10974981:"Shinobi (CCTV)",
            1274078387:"TP-LINK (Network Device)",
            -336242473:"Siemens OZW772",
            882208493:"Lantronix (Spider)",
            -687783882:"ClaimTime (Ramsell Public Health & Safety)",
            -590892202:"Surfilter SSL VPN Portal",
            -50306417:"Kyocera (Printer)",
            784872924:"Lucee!",
            1135165421:"Ricoh",
            926501571:"Handle Proxy",
            579239725:"Metasploit",
            -689902428:"iomega NAS",
            -600508822:"iomega NAS",
            656868270:"iomega NAS",
            -2056503929:"iomega NAS",
            -1656695885:"iomega NAS",
            331870709:"iomega NAS",
            1241049726:"iomega NAS",
            998138196:"iomega NAS",
            322531336:"iomega NAS",
            -401934945:"iomega NAS",
            -613216179:"iomega NAS",
            -276759139:"Chef Automate",
            1862132268:"Gargoyle Router Management Utility",
            -1738727418:"KeepItSafe Management Console",
            -368490461:"Entronix Energy Management Platform",
            1836828108:"OpenProject",
            -1775553655:"Unified Management Console (Polycom)",
            381100274:"Moxapass ioLogik Remote Ethernet I/O Server ",
            2124459909:"HFS (HTTP File Server)",
            731374291:"HFS (HTTP File Server)",
            -335153896:"Traccar GPS tracking",
            896412703:"IW",
            191654058:"Wordpress Under Construction Icon",
            -342262483:"Combivox",
            5542029:"NetComWireless (Network)",
            1552860581:"Elastic (Database)",
            1174841451:"Drupal",
            -1093172228:"truVision (NVR)",
            -1688698891:"SpamExperts",
            -1546574541:"Sonatype Nexus Repository Manager",
            -256828986:"iDirect Canada (Network Management)",
            1966198264:"OpenERP (now known as Odoo)",
            2099342476:"PKP (OpenJournalSystems) Public Knowledge Project",
            541087742:"LiquidFiles",
            -882760066:"ZyXEL (Network)",
            16202868:"Universal Devices (UD)",
            987967490:"Huawei (Network)",
            -647318973:"gm77[.]com",
            -1583478052:"Okazik[.]pl",
            1969970750:"Gitea",
            -1734573358:"TC-Group",
            -1589842876:"Deluge Web UI",
            1822002133:"登录 – AMH",
            -2006308185:"OTRS (Open Ticket Request System)",
            -1702769256:"Bosch Security Systems (Camera)",
            321591353:"Node-RED",
            -923693877:"motionEye (camera)",
            -1547576879:"Saia Burgess Controls – PCD",
            1479202414:"Arcadyan o2 box (Network)",
            1081719753:"D-Link (Network)",
            -166151761:"Abilis (Network/Automation)",
            -1231681737:"Ghost (CMS)",
            321909464:"Airwatch",
            -1153873472:"Airwatch",
            1095915848:"Airwatch",
            788771792:"Airwatch",
            -1863663974:"Airwatch",
            -1267819858:"KeyHelp (Keyweb AG)",
            726817668:"KeyHelp (Keyweb AG)",
            -1474875778:"GLPI",
            5471989:"Netcom Technology",
            -1457536113:"CradlePoint",
            -736276076:"MyASP",
            -1343070146:"Intelbras SA",
            538585915:"Lenel",
            -625364318:"OkoFEN Pellematic",
            1117165781:"SimpleHelp (Remote Support)",
            -1067420240:"GraphQL",
            -1465479343:"DNN (CMS)",
            1232159009:"Apple",
            1382324298:"Apple",
            -1498185948:"Apple",
            483383992:"ISPConfig",
            -1249852061:"Microsoft Outlook",
            999357577:"? (Possibly DVR)",
            492290497:"? (Possible IP Camera)",
            400100893:"? (DVR)",
            -1252041730:"Vue.js",
            180732787:"Apache Flink"
}

def print_banner():
    banner = """\u001b[32m
/$$$$$$$$                  /$$$$$$$$                          /$$        /$$$$$$      /$$$$$$ 
| $$_____/                 | $$_____/                         | $$       /$$__  $$    /$$$_  $$
| $$    /$$$$$$  /$$    /$$| $$    /$$$$$$  /$$$$$$   /$$$$$$ | $$   /$$|__/  \ $$   | $$$$\ $$
| $$$$$|____  $$|  $$  /$$/| $$$$$/$$__  $$/$$__  $$ |____  $$| $$  /$$/  /$$$$$$/   | $$ $$ $$
| $$__/ /$$$$$$$ \  $$/$$/ | $$__/ $$  \__/ $$$$$$$$  /$$$$$$$| $$$$$$/  /$$____/    | $$\ $$$$
| $$   /$$__  $$  \  $$$/  | $$  | $$     | $$_____/ /$$__  $$| $$_  $$ | $$         | $$ \ $$$
| $$  |  $$$$$$$   \  $/   | $$  | $$     |  $$$$$$$|  $$$$$$$| $$ \  $$| $$$$$$$$/$$|  $$$$$$/
|__/   \_______/    \_/    |__/  |__/      \_______/ \_______/|__/  \__/|________/__/ \______/ 



         \u001b[35m- FavFreak v2.0 | Coded with \u001b[31m<3\u001b[0m\u001b[35m by LiquidSec\u001b[0m
"""
    print(banner)

def build_urls(stdin, append_favicon=True):
    urls = []
    for line in stdin:
        base_url = line.strip()
        if append_favicon:
            if not base_url.endswith("/"):
                base_url += "/"
            base_url += "favicon.ico"
        urls.append(base_url)
    return urls


def fetch_url(url):
    try:
        response = requests.get(url, verify=False, timeout=10)
        favicon = codecs.encode(response.content, "base64")
        hash_val = mmh3.hash(favicon)
        md5_hash = hashlib.md5(response.content).hexdigest()
        return url, hash_val, md5_hash, None
    except Exception as e:
        return url, None, None, e


def analyze_favicons(urls, append_favicon):
    results_map = {}
    md5_map = {}
    results = ThreadPool(20).imap_unordered(fetch_url, urls)

    for url, hash_val, md5_hash, error in results:
        display_url = url.rsplit("/favicon.ico", 1)[0] if append_favicon else url
        if error:
            print(f"\u001b[31m[ERR]\u001b[0m Not Fetched {display_url}")
        else:
            print(f"\u001b[32m[INFO]\u001b[0m Fetched {display_url}")
            results_map.setdefault(hash_val, []).append(display_url)
            md5_map.setdefault(md5_hash, []).append(display_url)

    return results_map, md5_map

def query_shodan_by_hash(favicon_hash, api_key):
    api = shodan.Shodan(api_key)
    results = api.search(f"http.favicon.hash:{favicon_hash}")
    output = []
    for match in results["matches"]:
        ip = match.get("ip_str")
        port = match.get("port")
        hostnames = match.get("hostnames", [])
        line = f"{ip}:{port} {' '.join(hostnames)}"
        output.append(line)
    return output


def save_shodan_results(results_map, api_key, output_file):
    with open(output_file, "w") as f:
        for hash_val in results_map.keys():
            if hash_val != 0:
                try:
                    f.write(f"[Hash] {hash_val}\n")
                    shodan_data = query_shodan_by_hash(hash_val, api_key)
                    if shodan_data:
                        for line in shodan_data:
                            f.write(f"    {line}\n")
                    else:
                        f.write("    No results found.\n")
                    f.write("\n")
                except Exception as e:
                    f.write(f"    Error querying Shodan: {e}\n\n")
    print(f"\u001b[32m[+] Shodan results saved to: {output_file}\u001b[0m")

def print_results(results_map):
    print("\n" + "-" * 70)
    print("\u001b[32m[Favicon mmh3 Hash Results] - \u001b[0m\n")

    for hash_val, urls in results_map.items():
        print(f"\u001b[33m[Hash]\u001b[0m \u001b[32;1m{hash_val}\u001b[0m")
        for url in urls:
            print(f"     {url}")

def print_md5_results(md5_map):
    print("\n" + "-" * 70)
    print("\u001b[32m[Favicon md5 Hash Results] - \u001b[0m\n")
    for md5_hash, urls in md5_map.items():
        print(f"\u001b[33m[Hash]\u001b[0m \u001b[32;1m{md5_hash}\u001b[0m")
        for url in urls:
            print(f"     {url}")

def print_md5_fingerprints(md5_map):
    """Print results based on known fingerprints."""
    print("\n" + "-" * 70)
    for md5_hash, urls in md5_map.items():
        normalized_hash = md5_hash.strip().lower()
        if normalized_hash in md5_FINGERPRINTS:
            tech = md5_FINGERPRINTS[normalized_hash]
            print(f"[{tech}] {normalized_hash} - count: {len(urls)}")
            for url in urls:
                print(f"     {url}")

def print_fingerprints(results_map):
    """Print results based on known fingerprints."""
    print("\n" + "-" * 70)
    for hash_val, urls in results_map.items():
        if hash_val in FINGERPRINTS:
            tech = FINGERPRINTS[hash_val]
            print(f"[{tech}] {hash_val} - count: {len(urls)}")
            for url in urls:
                print(f"     {url}")


def print_uncover(results_map):
    print("\n" + "-" * 70)
    print("\u001b[32m[Uncover mode output] - \u001b[0m\n")
    for hash_val in results_map:
        if hash_val != 0:
            print(f"\u001b[34m[uncover]\u001b[0m uncover -q 'http.favicon.hash:{hash_val}' -e shodan,fofa,censys -silent")

def save_results(results_map, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for hash_val, urls in results_map.items():
        filename = output_path / f"{hash_val}.txt"
        with open(filename, "w") as f:
            f.write("\n".join(urls) + "\n")
    print(f"\n\u001b[32m[+] Output saved here: {output_path}\u001b[0m")


def print_summary(results_map, md5_map):
    print("\n" + "-" * 70)
    print("\u001b[32m[Summary]\u001b[0m\n")
    print(" \u001b[36mCount      \u001b[35mHash\u001b[0m")
    for hash_val, urls in results_map.items():
        print(f"~ \u001b[36m[{len(urls)}]  : \u001b[35m[{hash_val}]\u001b[0m")
    for md5_hash, urls in md5_map.items():
        print(f"~ \u001b[36m[{len(urls)}]  : \u001b[35m[{md5_hash}]\u001b[0m")


def main():
    parser = argparse.ArgumentParser(description="FavFreak2.0 - Favicon Hash Mapper (Modernized)")
    parser.add_argument("--output", help="Output directory for hash result files")
    parser.add_argument('--uncover', help='Uncover output mode for uncover tool from project discovery', action='store_true')
    parser.add_argument("--no-favicon", help="Do NOT append /favicon.ico to URLs", action="store_true")
    parser.add_argument("--shodan", help="Fetch IPs from Shodan using favicon hash", action="store_true")
    parser.add_argument("--api-key", help="Shodan API key (can also use SHODAN_API_KEY env var)")
    parser.add_argument("--shodan-output", help="Output file for Shodan results", default="shodan_results.txt")

    args = parser.parse_args()

    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    append_favicon = not args.no_favicon
    urls = build_urls(sys.stdin, append_favicon=append_favicon)

    print("[*] Fetching favicons...")
    start_time = timer()
    results_map, md5_map = analyze_favicons(urls, append_favicon)
    elapsed = timer() - start_time
    print(f"\n[*] Completed in {elapsed:.2f} seconds.")

    print_results(results_map)
    print_fingerprints(results_map)
    print_md5_results(md5_map)
    print_md5_fingerprints(md5_map)

    if args.uncover:
        print_uncover(results_map)

    if args.shodan:
        api_key = args.api_key or os.getenv("SHODAN_API_KEY")
        if not api_key:
            print("\u001b[31m[ERROR]\u001b[0m Shodan API key is required (pass via --api-key or set SHODAN_API_KEY)")
        else:
            save_shodan_results(results_map, api_key, args.shodan_output)

    if args.output:
        save_results(results_map, args.output)

    print_summary(results_map, md5_map)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\u001b[31m[EXIT] Keyboard Interrupt Encountered\u001b[0m")

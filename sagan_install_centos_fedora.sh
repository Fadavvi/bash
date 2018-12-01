RED='\033[0;31m'
NC='\033[0m'
echo ${RED}' ==============================\n'
echo '|  Sagan Installtion Script    |\n'
echo '|            V0.1              |\n'
echo '|      by Milad Fadavvi        |\n'
echo '|     Run Script as ROOT       |\n'
echo ' ==============================\n\n'
echo 'Step 1 : install Available Packages'
yum install -y git build-essential checkinstall autoconf pkg-config libtool libyaml-devel \
                    libesmtp-devel libpcap-devel pcre-devel geoip-devel gnutls-devel prelude-devel \
                    daq-devel glibc-static libestr-devel libfastjson-devel liblognorm-devel flex flow-tools \
                    rrdtool-devel rrdtool-perl flex flow-tools rrdtool-devel rrdtool-perl  byacc bison \
                    net-snmp net-snmp-perl snmptt  perl-Sys-Syslog
echo ${RED}'\n\nStep 2: Install GeoIP Lib & Database\n'${NC}
mkdir /usr/local/share/GeoIP
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
gunzip GeoLite2-City.mmdb.gz
mv GeoLite2-City.mmdb /usr/local/share/GeoIP/
git clone --recursive https://github.com/maxmind/libmaxminddb
cd libmaxminddb
./bootstrap
./configure
make check
make install
ldconfig -v
cd ..
echo ${RED}'\n\nStep 3: install libfastjson \n'${NC}
git clone https://github.com/rsyslog/libfastjson
cd libfastjson
./autogen.sh
./configure --libdir=/usr/lib --includedir=/usr/include
make && make install
ldconfig -v
cd ..
echo ${RED}'\n\nStep 4: install libestr \n'${NC}
git clone https://github.com/rsyslog/libestr
cd libestr/
autoreconf -vfi
./configure --libdir=/usr/lib --includedir=/usr/include
make && make install
ldconfig -v
cd ..
echo ${RED}'\n\nStep 5: install  liblognorm\n'${NC}
git clone https://github.com/rsyslog/liblognorm
cd liblognorm/
autoreconf -vfi
./configure --disable-docs --libdir=/usr/lib --includedir=/usr/include  --enable-regexp --enable-advanced-stats --enable-valgrind
make && make install
ldconfig -v
cd ..
echo ${RED}'\n\nStep 6: install libdnet\n'${NC}
git clone https://github.com/jncornett/libdnet
cd libdnet/
./configure && make && make install
ldconfig
cd ..
echo ${RED}'\n\nStep 7: install  Sagan\n'${NC}
git clone https://github.com/beave/sagan
cd sagan/
./autogen.sh
./configure --enable-geoip2 --enable-esmtp --enable-libpcap --enable-dependency-tracking
make && make install
ldconfig -v
cd .. 
echo ${RED}'\n\nStep 8: Install Barnyard2 for Sagan\n'${NC}
git clone https://github.com/firnsy/barnyard2
cd barnyard2*
./autogen.sh 
./configure --enable-prelude LIBS="-pthread"
make && make install
ldconfig -v
cd ..
echo ${RED}'\n\nStep 9: Install Netflow Support\n'${NC}
git clone https://github.com/beave/nfdump-1.6.10p1-sagan
cd nfdump-1.6.10p1-sagan
./configure --enable-sflow --enable-nfprofile --enable-nftrack --enable-sagan --enable-nsel
make && make install
ldconfig -v
echo ${RED}'\n\nStep 10: Install SNMPTrap Support\n'${NC}
echo 'OPTIONS="-On -Lsd -p /var/run/snmptrapd.pid"' >> /etc/sysconfig/snmptrapd
echo 'traphandle default /usr/sbin/snmptthandler' >> /etc/snmp/snmptrapd.conf
echo 'disableAuthorization yes' >> /etc/snmp/snmptrapd.conf
service snmptrapd start
chkconfig snmptrapd on
service snmptt start
chkconfig snmptt on
sh -c "echo /usr/local/lib  >> /etc/ld.so.conf.d/local.conf"
$ ldconfig -v
echo ${RED}'Notice!! you should change : \n'
echo '/usr/local/etc/sagan.yaml \n\n'
echo 'GeoIP file: /usr/local/share/GeoIP/GeoLite2-City.mmdb \n'
echo 'SNMP conf : /etc/snmp/snmptt.ini '
echo 'Netflow Tool: /usr/local/bin/nfcapd '
echo 'Rules are stored in: /usr/local/etc/sagan-rules'${NC}

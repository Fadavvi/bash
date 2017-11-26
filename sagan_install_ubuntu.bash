RED='\033[0;31m'
NC='\033[0m'
echo ${RED}' ==============================\n'
echo '|  Sagan Installtion Script    |\n'
echo '|            V0.1              |\n'
echo '|      by Milad Fadavvi        |\n'
echo '|     Run Script as ROOT       |\n'
echo ' ==============================\n\n'
echo 'Step 1 : install Available Packages'
echo 'Notice: I Choose MySQL! \n'${NC}
apt-get install git mysql-server libyaml-dev libtool autoconf libesmtp-dev libpcap-dev build-essential checkinstall libpcre3-dev libpcre3 libgeoip-dev pkg-config libgnutls28-dev libprelude-dev libdaq-dev libpthread-stubs0-dev
echo ${RED}'\n\nStep 2: Install GeoIP Lib & Database\n'${NC}
mkdir /usr/local/share/GeoIP
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
gunzip GeoLite2-City.mmdb.gz
mv GeoLite2-City.mmdb /usr/local/share/GeoIP/
git clone --recursive https://github.com/maxmind/libmaxminddb
cd libmaxminddb
./bootstrap
./configure
make check
make install
ldconfig
cd ..
echo ${RED}'\n\nStep 3: install libfastjson \n'${NC}
git clone https://github.com/rsyslog/libfastjson
cd libfastjson
./autogen.sh
./configure --libdir=/usr/lib --includedir=/usr/include
make && make install
ldconfig
cd ..
echo ${RED}'\n\nStep 4: install libestr \n'${NC}
git clone https://github.com/rsyslog/libestr
cd libestr/
autoreconf -vfi
./configure --libdir=/usr/lib --includedir=/usr/include
make && make install
ldconfig
cd ..
echo ${RED}'\n\nStep 5: install  liblognorm\n'${NC}
git clone https://github.com/rsyslog/liblognorm
cd liblognorm/
autoreconf -vfi
./configure --disable-docs --libdir=/usr/lib --includedir=/usr/include
make && make install
ldconfig
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
cd .. 
echo ${RED}'\n\nStep 8: Install Barnyard2 for Sagan\n'${NC}
git clone https://github.com/firnsy/barnyard2
cd barnyard2*
./autogen.sh 
./configure --enable-prelude LIBS="-pthread"
make && make install
cd ..
echo ${RED}'\n\nStep 9: download Sagan Rules\n'${NC}
cd /usr/local/etc
git clone https://github.com/beave/sagan-rules
echo ${RED}'\n\nStep X: Add Sagan user\n'${NC}
adduser sagan --disabled-password --disabled-login
mkdir /var/log/sagan
mkdir /var/run/sagan
mkdir /var/sagan/
mkdir /var/sagan/ipc
mkdir /var/sagan/fifo/
mkdir /var/log/sagan/stats
touch /var/log/sagan/stats/sagan.stats
chown -R sagan /var/sagan
chown -R sagan /var/run/sagan
chown -R sagan /var/sagan
chown -R sagan /var/log/
mkfifo /var/sagan/fifo/sagan.fifo

echo ${RED}'Notice!! you should change : \n'
echo '/usr/local/etc/sagan.yaml \n\n'
echo 'GeoIP file: /usr/local/share/GeoIP/GeoLite2-City.mmdb \n'
echo 'Rules are stored in: /usr/local/etc/sagan-rules'${NC}

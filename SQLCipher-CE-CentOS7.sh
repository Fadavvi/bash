export SQLITE_HAS_CODEC > /dev/null
export SQLITE_TEMP_STORE=2
cd /tmp/
echo -e '* Install OpenSSL/TCL/ReadLine and Git\n'
yum install openssl-devel tcl-devel readline-devel git -y > /dev/null
echo -e '* Clone SqlCipher Repo\n'
git clone --quiet https://github.com/sqlcipher/sqlcipher.git > /dev/null
cd /tmp/sqlcipher/
echo -e '* Config & Compile\n'
./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto" > /dev/null
make > /dev/null
make install > /dev/null
cp sqlcipher /usr/local/sbin/
echo -e 'SQLCipher Info:\n'
sqlcipher --version
exit 0

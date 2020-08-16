#!/usr/bin/env bash

export SQLITE_HAS_CODEC
export SQLITE_TEMP_STORE=2


yum install openssl-devel tcl-devel readline-devel git -y >> /dev/null

git clone https://github.com/sqlcipher/sqlcipher.git >> /dev/null

cd sqlcipher
./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto" >> /dev/null

make >> /dev/null

make install >> /dev/null

cp sqlcipher /usr/local/sbin/

sqlcipher --version

exit 0
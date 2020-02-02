#!/usr/bin/env bash
RED='\033[0;31m'
NC='\033[0m'
echo ${RED}' ==============================\n'
echo '|  IPA Uninstalltion Script    |\n'
echo '|            V0.1              |\n'
echo '|      by Milad Fadavvi        |\n'
echo '|     Run Script as ROOT       |\n'
echo ' ==============================\n\n'
echo 'Be careful - This Script will deleting all IPA data'
read -p "Are you sure? (y/n)" -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
    ipa-server-install -U --uninstall
    pushd /var/lib/ipa/
    rm -f ca*
    rm -f *.txt
    rm -f sysrestore/*
    popd
    pushd /var/lib/dirsrv/
    rm -rf scripts*
    popd
    pushd /etc/dirsrv/
    ls
    popd
    pushd /var/run/dirsrv/
    rm -rf slapd*
    ls
    popd
    pushd /etc/ipa
    rm -f ca.crt
    popd
    pushd /var/log/dirsrv
    rm -rf slapd*
    popd
    exit 1 || return 1
fi

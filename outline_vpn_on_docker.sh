#!/usr/bin/env bash
echo "Run script as root or with sudo"
yum install -y curl wget > /dev/null
curl -sS https://get.docker.com/ | sh
systemctl start docker
systemctl enable docker
wget -qO- https://raw.githubusercontent.com/Jigsaw-Code/outline-server/master/src/server_manager/install_scripts/install_server.sh | bash

authconfig --passalgo=sha512 --update
systemctl mask ctrl-alt-del.target
echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth
yum install epel-release -y && yum update -y
yum install ntp ntpdate -y
systemctl enable ntpdat && systemctl start ntpd
echo "NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/disabled.conf
echo "net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
sysctl -q -n -w kernel.randomize_va_space=2




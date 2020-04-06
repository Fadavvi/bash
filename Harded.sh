#!/usr/bin/env bash
RED='\033[0;31m'
NC='\033[0m'
echo ${RED}' ==============================\n'
echo '| CentOS/RHEL/Fedora Harded.sh |\n'
echo '|            V0.13             |\n'
echo '|        by Milad Fadavvi      |\n'
echo '|       Run Script as ROOT     |\n'
echo ' ==============================\n\n'${RED}
echo 'Kernel level configuration will change.'
read -p "Are you sure? (y/n)" -n 1 -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]
then
    authconfig --passalgo=sha512 --update
    systemctl mask ctrl-alt-del.target
    echo "ALL:ALL" >> /etc/hosts.deny
    echo "sshd:ALL" >> /etc/hosts.allow
    sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth
    yum install epel-release -y && yum update -y > /dev/nill
    yum install ntp ntpdate -y > /dev/null
    systemctl enable ntpdat && systemctl start ntpd
    echo "NOZEROCONF=yes
    NETWORKING_IPV6=no
    IPV6INIT=no" >> /etc/sysconfig/network
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
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
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" > /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
    echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/audit.rule
    echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rule
    echo "-w /usr/share/selinux/ -p wa -k MAC-policy" > /etc/audit/audit.rule
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rule
    echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/audit.rule
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rule
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/audit.rule
    echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 –F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 –F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown –F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown –F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr –S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr –S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate –S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate –S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate –S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate –S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rule
    echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rule
    echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/audit.rule
    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rule
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rule
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rule
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rule
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rule
    echo "-e 2" >> /etc/audit/audit.rule
    pkill auditd
    systemctl start auditd
    sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
    sed -i 's/#Banner none/Banner \/etc\/issue.net /g' /etc/ssh/sshd_config
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
    systemctl restart sshd
fi



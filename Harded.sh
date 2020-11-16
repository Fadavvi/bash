#!/usr/bin/env bash
###### Script Colors
RED='\e[31m'
YELLOW='\e[33m'
GREEN='\e[32m'
INVERT='\e[7m'
NC='\033[0m'
###### Password Related Variables
EXPIRE_PASS='60'
MINLENTH='12'
PASSWORDAGE='14'
CHANGEPASSATADAY='1'
echo -e ${RED}' ==============================\n'
echo -e '| CentOS/RHEL/Fedora Hardening |\n'
echo -e '|   Script for ISMS(ISO27001)  |\n'
echo -e '|           V 0.25             |\n'
echo -e '|      by Milad Fadavvi        |\n'
echo -e '|    * Run Script as ROOT *    |\n'
echo -e ' ==============================\n\n'
echo -e 'Kernel level configuration will change.'${NC}
read -p "Are you sure? (y/n)" -n 1 -r $REPLY
if [[ $REPLY =~ ^[Nn]$ ]]; then
    exit 1
fi
print -e ${INVERT}' Script will disable SELinux for changing configs.'${NC}
setenforce 0 > /dev/null
echo -e '\n'

echo -e ${GREEN}'* Changing password hash algorithem : SHA512'${NC}
authconfig --passalgo=sha512 --update > /dev/null
sleep 5s

echo -e ${GREEN}'* Disabling core dump'
echo '* hard core 0' > /etc/security/limits.conf
sleep 5s

echo -e ${GREEN}'* Remove default users'${NC}
userdel -f games 2>/dev/null
userdel -f news 2>/dev/null
userdel -f gopher 2>/dev/null
userdel -f tcpdump 2>/dev/null
userdel -f shutdown 2>/dev/null
userdel -f halt 2>/dev/null
userdel -f sync 2>/dev/null
userdel -f ftp 2>/dev/null
userdel -f operator 2>/dev/null
userdel -f lp 2>/dev/null
userdel -f uucp 2>/dev/null
userdel -f irc 2>/dev/null
userdel -f gnats 2>/dev/null
userdel -f pcap 2>/dev/null
userdel -f netdump 2>/dev/null
sleep 5s

echo -e ${GREEN}'* Disbale/password-protected single user mode'${NC}
sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init
sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init
sleep 5s

echo -e ${GREEN}'* Changing password expire parameters'${NC}
sed -i "s/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS $EXPIRE_PASS/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS $PASSWORDAGE/" /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*$/PASS_WARN_AGE $PASSWORDAGE/" /etc/login.defs
sleep 5s

echo -e ${GREEN}'* Disable restart with ctrl-alt-del'${NC}
systemctl mask ctrl-alt-del.target >> /dev/null 
sleep 5s

echo -e ${GREEN}'* Add sshd to /etc/hosts.allow & deny other services'${NC}
echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow
sleep 5s

echo -e ${GREEN}'* Remove blank password option from PAM'${NC}
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth
sleep 5s

echo -e ${GREEN}"* Minimum password lenght: $MINLENTH Char"${NC}
authconfig --passminlen=$MINLENTH --update > /dev/null
sleep 5s

echo -e ${GREEN}'* Minimum char classes in password: 3 classes'${NC}
authconfig --passminclass=3 --update > /dev/null
sleep 5s

echo -e ${RED}'* Update with YUM / install NTPD / install clamAV'${NC}
read -p "Do you want to process? (y/n)" -n 1 -r REPLY
echo -e '\n'
if [[ $REPLY =~ ^[Yy]$ ]]; then
    yum install epel-release -y && yum update -y && yum upgrade -y > /dev/null
    yum install ntp ntpdate -y > /dev/null
    yum install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y > /dev/null
    systemctl enable ntpdate > /dev/null 
    systemctl start ntpd > /dev/null
    setsebool -P antivirus_can_scan_system 1
    setsebool -P clamd_use_jit 1
    sed -i -e "s/^Example/#Example/" /etc/freshclam.conf
    freshclam > /dev/null
    systemctl enable clamd@scan > /dev/null
    systemctl enable freshclam > /dev/null
    systemctl start clamd@scan > /dev/null
    systemctl start freshclam > /dev/null
    sleep 5s
fi

echo -e ${GREEN}'* Remove Zero Conf NIC & IPv6 options'${NC}
echo "NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/disabled.conf
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/ipv6.conf
sleep 5s

echo -e ${GREEN}'* Write a banner for SSH/tty Logins'${NC}
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/motd 
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net
chown -f root:root /etc/motd /etc/issue*
chmod -f 0444 /etc/motd /etc/issue*
sleep 5s

echo -e ${GREEN}'* Kernel level parameters'${NC}
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
kernel.dmesg_restrict=1
kernel.kptr_restrict=1
kernel.kexec_load_disabled=1
kernel.yama.ptrace_scope=1
user.max_user_namespaces=0
net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
sysctl -q -n -w kernel.randomize_va_space=2
sleep 5s

echo -e ${GREEN}'* Write audit rules & resetart the service'${NC}
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
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 â€“F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 â€“F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown â€“F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown â€“F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr â€“S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr â€“S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate â€“S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate â€“S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate â€“S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate â€“S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rule
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
echo "-w /usr/bin/passwd -p x -k passwd_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/groupadd -p x -k group_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/groupmod -p x -k group_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/addgroup -p x -k group_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/useradd -p x -k user_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/userdel -p x -k user_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/usermod -p x -k user_modification" >> /etc/audit/audit.rule
echo "-w /usr/sbin/adduser -p x -k user_modification" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S ptrace -k tracing" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S ptrace -k tracing" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection" >> /etc/audit/audit.rule
echo "-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection" >> /etc/audit/audit.rule
echo "-e 2" >> /etc/audit/audit.rule
pkill auditd
/sbin/chkconfig --level 12345 auditd on 2>/dev/null
systemctl start auditd >> /dev/null
systemctl enable auditd >> /dev/null
sleep 5s

echo -e ${GREEN}'* set file and folders ownership/premisions'
chown -f root:sys /dev/kmem
chown -f root:sys /dev/mem
chown -f root:sys /dev/null
chown -f root:root /etc/aliases
chown -f root:root /etc/exports
chown -f root:root /etc/passwd
chown -f root:root /etc/shadow
chown -f root /sbin/ausearch
chown -f root /sbin/aureport
chown -f root:root /var/crash
chown -f root:root /var/cache/mod_proxy
chown -f root:root /var/lib/dav
chown -f root:root /usr/bin/lockfile
chown -f root:root /etc/audit/audit.rules
chown -f root:root /etc/audit/auditd.conf
chown -f adm:adm /var/adm
chown -f rpcuser:rpcuser /var/lib/nfs/statd
chown -f root:root /bin/mail
chown -f root /sbin/auditd
chmod -f 0600 /var/crash
chmod -f 1777 /tmp
chown -f root:root /root
chown -f root:sys /etc/cups/client.conf
chown -f root:sys /etc/cups/cupsd.conf
chown -f root:root /etc/grub.conf
chown -f root:root /boot/grub2/grub.cfg
chown -f root:root /boot/grub/grub.cfg
chown -f root:root /etc/hosts
chown -f root:root /etc/inittab
chown -f root:bin /etc/mail/sendmail.cf
chown -f root:root /etc/sudoers
chown -f root:root /etc/sysctl.conf
chown -f root:root /etc/sysctl.d/*
chown -f root:root /var/log
chown -Rf root:root /var/log/*
chown -f root:tty /usr/bin/wall
chown -f root:users /mnt
chown -f root:users /media
chown -f root:root /bin/traceroute
chown -f root /etc/security/environ
chown -f root /etc/xinetd.d
chown -f root /etc/xinetd.d/*
chown -f root:root /usr/bin/traceroute6
chown -f root:root /dev/audio
chown -f root:root /etc/environment
chown -f root:root /etc/modprobe.conf
chown -f root:root /etc/modprobe.d
chown -f root:root /etc/modprobe.d/*

chmod -f 0640 /etc/sysconfig/selinux
chmod -f 0600 /etc/passwd
chmod -f 0400 /etc/shadow
chmod 600 ~/.ssh/* > /dev/null
chmod -f 0700 /sbin/reboot
chmod -f 0700 /sbin/shutdown
chmod -f 0600 /etc/ssh/ssh*config
chmod -f 0700 /root
chmod -f 0500 /usr/bin/ypcat
chmod -f 0700 /usr/sbin/usernetctl
chmod -f 0700 /usr/bin/rlogin
chmod -f 0700 /usr/bin/rcp
chmod -f 0640 /etc/pam.d/system-auth*
chmod -f 0640 /etc/login.defs
chmod -f 0750 /etc/security
chmod -f 0600 /etc/audit/audit.rules
chmod -f 0600 /etc/audit/auditd.conf
chmod -f 0600 /etc/auditd.conf
chmod -f 0744 /etc/rc.d/init.d/auditd
chown -f root /sbin/auditctl
chmod -f 0750 /sbin/auditctl
chmod -f 0750 /sbin/auditd
chmod -f 0750 /sbin/ausearch
chmod -f 0750 /sbin/aureport
chown -f root /sbin/autrace
chmod -f 0750 /sbin/autrace
chown -f root /sbin/audispd
chmod -f 0750 /sbin/audispd
chmod -f 0444 /etc/bashrc
chmod -f 0444 /etc/csh.cshrc
chmod -f 0444 /etc/csh.login
chmod -f 0600 /etc/cups/client.conf
chmod -f 0600 /etc/cups/cupsd.conf
chmod -f 0600 /etc/grub.conf
chmod -f 0600 /boot/grub2/grub.cfg
chmod -f 0600 /boot/grub/grub.cfg
chmod -f 0444 /etc/hosts
chmod -f 0600 /etc/inittab
chmod -f 0444 /etc/mail/sendmail.cf
chmod -f 0600 /etc/ntp.conf
chmod -f 0640 /etc/security/access.conf
chmod -f 0600 /etc/security/console.perms
chmod -f 0600 /etc/security/console.perms.d/50-default.perms
chmod -f 0600 /etc/security/limits
chmod -f 0444 /etc/services
chmod -f 0444 /etc/shells
chmod -f 0644 /etc/skel/.*
chmod -f 0600 /etc/skel/.bashrc
chmod -f 0600 /etc/skel/.bash_profile
chmod -f 0600 /etc/skel/.bash_logout
chmod -f 0440 /etc/sudoers
chmod -f 0600 /etc/sysctl.conf
chmod -f 0700 /etc/sysctl.d
chmod -f 0600 /etc/sysctl.d/*
chmod -f 0600 /etc/syslog.conf
chmod -f 0600 /var/yp/binding
chmod -Rf 0640 /var/log/*
chmod -Rf 0640 /var/log/audit/*
chmod -f 0755 /var/log
chmod -f 0750 /var/log/syslog /var/log/audit
chmod -f 0600 /var/log/lastlog*
chmod -f 0600 /var/log/cron*
chmod -f 0600 /var/log/btmp
chmod -f 0660 /var/log/wtmp
chmod -f 0444 /etc/profile
chmod -f 0700 /etc/rc.d/rc.local
chmod -f 0400 /etc/securetty
chmod -f 0700 /etc/rc.local
chmod -f 0750 /usr/bin/wall
chmod -f 0644 /etc/.login
chmod -f 0644 /etc/profile.d/*
chmod -f 0750 /etc/xinetd.d
chmod -f 0640 /etc/xinetd.d/*
chmod -f 0640 /etc/selinux/config
chmod -f 0750 /usr/bin/chfn
chmod -f 0750 /usr/bin/chsh
chmod -f 0750 /usr/bin/write
chmod -f 0700 /etc/cron.monthly/*
chmod -f 0700 /etc/cron.weekly/*
chmod -f 0700 /etc/cron.daily/*
chmod -f 0700 /etc/cron.hourly/*
chmod -f 0700 /etc/cron.d/*
chmod -f 0400 /etc/cron.allow
chmod -f 0400 /etc/cron.deny
chmod -f 0400 /etc/crontab
chmod -f 0400 /etc/at.allow
chmod -f 0400 /etc/at.deny
chmod -f 0700 /etc/cron.daily
chmod -f 0700 /etc/cron.weekly
chmod -f 0700 /etc/cron.monthly
chmod -f 0700 /etc/cron.hourly
chmod -f 0700 /var/spool/cron
chmod -f 0600 /var/spool/cron/*
chmod -f 0700 /var/spool/at
chmod -f 0600 /var/spool/at/*
chmod -f 0400 /etc/anacrontab
chmod -f 0750 /sbin/mount.nfs
chmod -f 0750 /sbin/mount.nfs4
chmod -f 0700 /usr/bin/ldd
chmod -f 0700 /bin/traceroute
chmod -f 0700 /usr/bin/traceroute6*
chmod -f 0700 /bin/tcptraceroute
chmod -f 0700 /sbin/iptunnel
chmod -f 0700 /usr/bin/tracpath*
chmod -f 0644 /dev/audio  
chmod -f 0644 /etc/environment   
chmod -f 0600 /etc/modprobe.conf
chmod -f 0700 /etc/modprobe.d
chmod -f 0600 /etc/modprobe.d/*
chmod -f o-w /selinux/*
chmod -f 0755 /etc
chmod -f 0644 /usr/share/man/man1/*
chmod -Rf 0644 /usr/share/man/man5
chmod -Rf 0644 /usr/share/man/man1
chmod -f 0600 /etc/yum.repos.d/*
chmod -f 0640 /etc/fstab
chmod -f 0755 /var/cache/man
chmod -f 0755 /etc/init.d/atd
chmod -f 0750 /etc/ppp/peers
chmod -f 0755 /bin/ntfs-3g
chmod -f 0750 /usr/sbin/pppd
chmod -f 0750 /etc/chatscripts
chmod -f 0750 /usr/local/share/ca-certificates
sleep 5s

echo -e ${GREEN}'* SSHD Hardening & restart the service'${NC}
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#Banner none/Banner \/etc\/issue.net /g' /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
systemctl restart sshd
sleep 5s

echo -e ${GREEN}'* Disable useless/old file systems'${NC}
echo 'install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true' >> /etc/modprobe.d/CIS.conf 
sleep 5s

echo -e ${GREEN}' * Disabling USB cooldisk/Flash mount'${NC}
/sbin/grubby --update-kernel=ALL --args="nousb"
sleep 5

echo -e ${INVERT}' Script will enable SELinux after changing configs.'${NC}
setenforce 1 > /dev/null

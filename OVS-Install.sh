echo -e " OVS installation script\n"
echo -e "-=-=-=-=-=-=-=-=-=-=-=-=-=-\n"
echo -e "1) EPEL repository\n"
echo -e "2) EL repository\n"
echo -e "P.S.: EL may have new kernels for CentOS 7\n"
echo -n "Which one? : "
read Repo
case "$Repo" in
    1)
        yum install epel-release -y > /dev/null
        trap 'echo Error at about $LINENO' ERR
        echo -e "Done: EPEL repo\n"
    2)
        yum install epel-release -y > /dev/null
        yum install https://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm -y > /dev/null
        trap 'echo Error at about $LINENO' ERR
        echo -e "Done: EL Repo\n"
echo -e "Installing devel tools:\n"        
yum group install "Development Tools" -y > /dev/null
trap 'echo Error at about $LINENO' ERR
echo -e "Done: Devel Tools\n"
echo -e "Installing necesaary & optional [but recommended] Libs/packages:\n" 
case "$Repo" in
    1)
        yum install openssl-devel libcap-ng python36 python36-pip unbound-libs unbound-devel kernel \
                    kernel-headers kernel-devel wget nc curl net-tools git > /dev/null
    2)
        yum install openssl-devel libcap-ng python36 python36-pip unbound-libs unbound-devel kernel-el \
                    kernel-el-headers kernel-el-devel wget nc curl net-tools git > /dev/null
trap 'echo Error at about $LINENO' ERR
python3.6 -m pip install pyftpdlib tftpy > /dev/null
trap 'echo Error at about $LINENO' ERR
cd /opt/
echo -e "Cloning OVS source code from Git:\n"
git clone https://github.com/openvswitch/ovs.git > /dev/null
trap 'echo Error at about $LINENO' ERR
cd ovs*
echo -e "Compile OVS codes\n"
./boot.sh > /dev/null
trap 'echo Error at about $LINENO' ERR
./configure > /dev/null
trap 'echo Error at about $LINENO' ERR
make > /dev/null
trap 'echo Error at about $LINENO' ERR
make install > /dev/null
trap 'echo Error at about $LINENO' ERR
config_file="/etc/depmod.d/openvswitch.conf"
for module in datapath/linux/*.ko; do
  modname="$(basename ${module})"
  echo "override ${modname%.ko} * extra" >> "$config_file"
  echo "override ${modname%.ko} * weak-updates" >> "$config_file"
done
depmod -a
echo -e "Loading the kernel module :\n"
/sbin/modprobe openvswitch
trap 'echo Error at about $LINENO' ERR
echo -e "Testing loaded moduled:\n"
/sbin/lsmod | grep openvswitch
echo -e "Additional actions:\n"
export PATH=$PATH:/usr/local/share/openvswitch/scripts
ovs-ctl start
trap 'echo Error at about $LINENO' ERR
echo -e "OVS is read to use\nPleaseead the manual."

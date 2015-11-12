#!/bin/bash
 
if [[ $EUID -ne 0 ]]; then
   echo "Root privileges required" 
   exit 1
fi

mkdir -p "/opt/ovs/"
mkdir -p "/opt/ovs/src"

echo "Downloading OpenvSwitch 2.4.0"
curl http://openvswitch.org/releases/openvswitch-2.4.0.tar.gz | tar -xzC "/opt/ovs/src"

echo "Installing OVS"
cd "/opt/ovs/src/openvswitch-2.4.0"
./configure --prefix=/opt/ovs/2.4.0 --with-linux=/lib/modules/`uname -r`/build
make
make install
make modules_install
/sbin/modprobe openvswitch
cp "/opt/ovs/src/openvswitch-2.4.0/datapath/linux/openvswitch.ko" "/opt/ovs/2.4.0/sbin"

echo "Done!!"

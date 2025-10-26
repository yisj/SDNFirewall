#!/bin/bash
# CS 6250 Spring 2021 - SDN Firewall Project with POX
# build leucosia-v20

# This code will start up the POX firewall.  This needs to be done BEFORE starting the
# topology, otherwise you will get an Unable to Contact Remote Controller error from
# Mininet.


if [ ! -d ~/pox/pox/firewall ]; then
  mkdir ~/pox/pox/firewall
fi

cp alternate-configure.pol ~/pox/pox/firewall/config.pol
cp sdn-firewall.py ~/pox/pox/firewall/sdnfirewall.py
cp setup-firewall.py ~/pox/pox/firewall/setupfirewall.py
pushd ~/pox
#python pox.py log.level --DEBUG openflow.of_01 forwarding.l2_learning firewall.setupfirewall
python pox.py openflow.of_01 forwarding.l2_learning firewall.setupfirewall
popd
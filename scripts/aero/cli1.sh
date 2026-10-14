ulimit -S -c unlimited
/usr/local/sbin/aerod -T Client -C /usr/local/etc/aerod/conf/files/aero/Client1/aerod.json -i eth2 &
sleep 3
rm /root/.ssh/known_hosts
sleep 3
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.eth1.forwarding=1
sysctl -w net.ipv6.conf.eth2.forwarding=1

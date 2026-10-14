ulimit -S -c unlimited
/usr/local/sbin/aerod -T Client -C /usr/local/etc/aerod/conf/files/aero/Client2/aerod.json &
sleep 3
rm /root/.ssh/known_hosts

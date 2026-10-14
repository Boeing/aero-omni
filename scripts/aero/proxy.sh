ulimit -S -c unlimited
/usr/sbin/rsyslogd
/usr/local/sbin/aerod -d -T Proxy -C /usr/local/etc/aerod/conf/files/aero/Proxy/aerod.json
sleep 1
rm -rf /usr/local/var/run/kea/*
rm -rf /var/run/kea*
/usr/local/sbin/keactrl start -c /usr/local/etc/aerod/conf/files/aero/Proxy/keactrl.conf
/usr/local/sbin/radvd -C /usr/local/etc/aerod/conf/files/aero/Proxy/radvd.conf

Script that compares the current time with the last time the Ossec
syscheck process ran in every agent. If it has been more
than 60 minutes (assuming that Ossec syscheck will be set to 
run every 30 minutes), do not send a "0" signal to Zabbix
but log it in /var/log/messages. Zabbix will then realize
that it did not receive a "0" within an interval of time,
and trigger an alarm. 

Script assumes the Zabbix trapper (item) Key is "trapper.ossec.informer"
and the Trigger's expression is `{host.name:trapper.ossec.informer.nodata(30m)}=1`


Cronjob should be set to run every 30 minutes

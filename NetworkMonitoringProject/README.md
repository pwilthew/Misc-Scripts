## Network Monitoring Project
 
The purpose of this project is to build a database with all the found MAC addresses on an office's switch. I used `snmpwalk` to get all the needed information from the switch.

The script `poll_switch.py` would initially create a database table and populate it. The same script can be used to alert if a device appears on the network; the block of SQL DROP and CREATE tables under main should be commented. Every instance of `#Alert` should be replaced by an actual alert sender, such as `zabbix_sender`.

The script is able to determine if:

* A new device appears on the network.
* A new MAC, that is not proprietary of Cisco, appears on the network on a VLAN known to be for phones.
* A MAC appears on the MAC table but does not appear on the ARP table; the device is not using IPv4.
* A MAC shows up on a VLAN in which is is now allowed; the `allowed_vlan_list` column of the database table should be manually entered in the format "100, 120, 300", for example.

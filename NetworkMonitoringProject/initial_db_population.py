#!/usr/bin/python
"""Usage: ./initial_db_population.py

The purpose of this script is to populate a database with
information about the devices connected to a switch 
stack Cisco 2960XR."""

import MySQLdb
import subprocess
    
# OID RFC1213-MIB::atPhysAddress
ARP_TABLE_OID = '.1.3.6.1.2.1.3.1.1.2'
IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'

# Open file with database credentials
file_name = '/../...'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open file with SNMP credentials and the database table name that will
# store the devices connected to the switch 
file_name = '/../...'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]


def insert_macs_vlans_ips():
    """Inserts into database the physical address, vlan, and most recent ipv4 
    address of device found through snmpwalk."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
           '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, ARP_TABLE_OID]

    arp_table = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
    arp_table_list = table.splitlines()

    for row in arp_table_list:
        string, mac_in_hex = (row.split(' = Hex-STRING: '))[0:2]

        mac_in_hex = (mac_in_hex.strip(' ')).split(' ')
        mac = mac_in_hex[0] + mac_in_hex[1] + '.' +\
              mac_in_hex[2] + mac_in_hex[3] + '.' +\
              mac_in_hex[4] + mac_in_hex[5]
 
        vlan = (string.split('::atPhysAddress.')[1]).split('.')[0]
        dot = '.'
        ip = dot.join(((string.split('::atPhysAddress.')[1]).split('.'))[2:6])

        insert = "INSERT INTO " + table_name + "(MAC, VLAN, MOST_RECENT_IPV4) VALUES\
                 ('%s', '%s', '%s')" % (mac, vlan, ip)

        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in DB insertion'
            db.rollback()


def insert_descriptions():
    """Inserts into database the description of each device found through 
    snmpwalk."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
           '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, IF_DESCRIPTION]

    if_descr = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
    if_descr_list = table.splitlines()

    for row in if_descr_list:
        print row
        #in construction    

def main():

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Retrieve SNMP information and insert in database
    insert_macs_vlans_ips()

    # Close database connection
    db.close()


if __name__ == '__main__':
    main()
 

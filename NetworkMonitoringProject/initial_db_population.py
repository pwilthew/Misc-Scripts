#!/usr/bin/python
"""Usage: ./initial_db_population.py

The purpose of this script is to populate a database with
information about the devices connected to a switch 
stack Cisco 2960XR."""

import MySQLdb
import subprocess

# Global dictionary of Interface Index ID => MAC address
dic_if_mac = {}

# Gloval VLAN's IDs list
VLANS_IDS = []
    
# OID RFC1213-MIB::atPhysAddress
ARP_TABLE_OID = '.1.3.6.1.2.1.3.1.1.2'
IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'

# Open file with database credentials
file_name = '/var/www/vhosts/netwatch.mivamerchant.net/private/db_creds.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open database connection
db = MySQLdb.connect(user=username,db=db_name,passwd=password)

# Open file with SNMP credentials and the database table name that will
# store the devices connected to the switch 
file_name = '/var/www/vhosts/netwatch.mivamerchant.net/private/snmp_tampa_switch.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]


def populate_vlans_ids():
    """Populates a gobal list of the found VLANs IDs."""
    arg = ['-m' + 'BRIDGE-MIB:CISCO-IF-EXTENSION-MIB:CISCO-VLAN-IFTABLE-RELATIONSHIP-MIB:IF-MIB', 
           '-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
           '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, 'vtpVlanState']

    out = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
    out_list = out.splitlines()

    for item in out_list:
        vlan = (item.split(' = ')[0]).split('.')[-1]
        
        if int(vlan) > 1 and int(vlan) < 1000:
            VLANS_IDS.append(vlan)

    return


def insert_in_db():
    """Inserts into database the information of each device found 
    through snmpwalk."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
           '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, ARP_TABLE_OID]

    arp_table = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
    arp_table_list = arp_table.splitlines()

    for row in arp_table_list:
        string, mac_in_hex = (row.split(' = Hex-STRING: '))[0:2]

        mac_in_hex = (mac_in_hex.strip(' ')).split(' ')
        mac = mac_in_hex[0] + mac_in_hex[1] + '.' +\
              mac_in_hex[2] + mac_in_hex[3] + '.' +\
              mac_in_hex[4] + mac_in_hex[5]
 
        vlan = (string.split('::atPhysAddress.')[1]).split('.')[0]
        dot = '.'
        ip = dot.join(((string.split('::atPhysAddress.')[1]).split('.'))[2:6])

#        insert = "INSERT INTO " + table_name + "(MAC, VLAN, MOST_RECENT_IPV4) VALUES\
#                 ('%s', '%s', '%s')" % (mac, vlan, ip)

#        try:
#            cursor.execute(insert)
#            db.commit()

#        except:
#            print 'Error in DB insertion'
#            db.rollback()


def get_descriptions():
    """Inserts into database the description of each device found through 
    snmpwalk."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
           '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, IF_DESCRIPTION_OID]

    if_descr = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
    if_descr_list = if_descr.splitlines()

    return if_descr_list


def populate_indexes_and_macs():
    """Returns a dictionary of interface indexes and their respective MAC addresses."""

    for vlan in VLANS_IDS:
        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
               '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, 'BasePortIfIndex']

        output = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
        baseport_index_list = output.splitlines()


        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
               '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, 'dot1dTpFdbPort']

        output = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
        mac_baseport_list = output.splitlines()


        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user, '-a' + auth_protocol,\
               '-A' + auth_password, '-x' + priv, '-X' + priv_password, host, 'dot1dTpFdbAddress']

        output = subprocess.Popen(['snmpwalk'] + arg, stdout=subprocess.PIPE).communicate()[0]
        mac_address_list = output.splitlines()

        # Temporary dictionaries to store the mapping baseport => MAC Address and
        #                                             baseport => Interface Index ID
        dic_baseport_mac = {}
        dic_baseport_index = {}

        # Populate dic_baseport_mac dictionary
        for i,j in zip(mac_baseport_list, mac_address_list):
            baseport = i.split('INTEGER: ')[-1]
            mac = j.split('STRING: ')[-1]
            dic_baseport_mac[baseport] = mac

        # Populate dic_baseport_index dictionary
        for item in baseport_index_list:
            first, second = item.split(' = ')[0:2]
            baseport = first.split('.')[-1]
            if_index = second.split(': ')[-1]
            dic_baseport_index[baseport] = if_index

        # Populate the dic_if_mac dictionary
        for baseport in dic_baseport_mac.keys():
            if_index = dic_baseport_index[baseport]
            mac = dic_baseport_mac[baseport]
            dic_if_mac[if_index] = mac 

    return


def insert_indexes_and_macs():
    
    for index in dic_if_mac.keys():
        insert = "INSERT INTO " + table_name + "(IF_INDEX, MAC) VALUES\
                 ('%s', '%s')" % (index, dic_if_mac[index])

        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in DB insertion'
            db.rollback()


def main():

    # Prepare a cursor object
    cursor = db.cursor()

    # Retrieve VLAN ids
    populate_vlans_ids()

    # Retrieve interfaces' indexes and macs
    populate_indexes_and_macs()

    # Insert interfaces' indexes and macs into DB
    insert_indexes_and_macs()

    # Close database connection
    db.close()


if __name__ == '__main__':
    main()
 

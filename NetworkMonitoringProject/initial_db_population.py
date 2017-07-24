#!/usr/bin/python
"""Usage: ./initial_db_population.py

The purpose of this script is to populate a database with
information about the devices connected to a switch 
stack Cisco 2960XR."""
import MySQLdb
import subprocess
import re

# Global dictionary of Interface Index ID => [MAC address, VLAN]
dic_if_mac_vlan = {}

# Gloval VLAN's IDs list
VLANS_IDS = []
    
# OIDs
ARP_TABLE_OID = '.1.3.6.1.2.1.3.1.1.2'
IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'
VLAN_IF_TABLE = 'BRIDGE-MIB:CISCO-IF-EXTENSION-MIB:CISCO-VLAN-IFTABLE-RELATIONSHIP-MIB:IF-MIB'

# Open file with database credentials
file_name = '/db_creds.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open file with SNMP credentials and the database table name that will
# store the devices connected to the switch 
file_name = '/snmp_creds.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]


def populate_vlans_ids():
    """Populates a gobal list of the found VLANs IDs."""
    arg = ['-m' + VLAN_IF_TABLE, '-v' + version, '-l' + security,\
           '-u' + user, '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host, 'vtpVlanState']

    out = subprocess.Popen(['snmpwalk'] + arg, 
                           stdout=subprocess.PIPE).communicate()[0]
    out_list = out.splitlines()

    for item in out_list:
        vlan = (item.split(' = ')[0]).split('.')[-1]
        
        if int(vlan) > 1 and int(vlan) < 1000:
            VLANS_IDS.append(vlan)

    return


def retrieve_indexes_macs():
    """Populates the global dictionary of interface indexes and their\
    respective MAC addresses and VLANs (dic_if_mac_vlan)."""

    for vlan in VLANS_IDS:
        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'BasePortIfIndex']

        output = subprocess.Popen(['snmpwalk'] + arg, 
                                  stdout=subprocess.PIPE).communicate()[0]
        
        baseport_index_list = output.splitlines()


        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'dot1dTpFdbPort']

        output = subprocess.Popen(['snmpwalk'] + arg,
                                  stdout=subprocess.PIPE).communicate()[0]

        mac_baseport_list = output.splitlines()


        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'dot1dTpFdbAddress']

        output = subprocess.Popen(['snmpwalk'] + arg,
                                  stdout=subprocess.PIPE).communicate()[0]

        mac_address_list = output.splitlines()

        # Temporary dictionaries to represent the mapping 
        # baseport => MAC Address and
        # baseport => Interface Index ID
        dic_baseport_mac = {}
        dic_baseport_index = {}

        # Parse lists' items to get baseport and mac to populate
        # dic_baseport_mac dictionary
        for i,j in zip(mac_baseport_list, mac_address_list):
            baseport = i.split('INTEGER: ')[-1]
            mac = j.split('STRING: ')[-1]
            dic_baseport_mac[baseport] = mac

        # Parse lists' items to get baseport and if index to populate
        # dic_baseport_index dictionary
        for item in baseport_index_list:
            first, second = item.split(' = ')[0:2]
            baseport = first.split('.')[-1]
            if_index = second.split(': ')[-1]
            dic_baseport_index[baseport] = if_index

        # Populate the global dic_if_mac_vlan dictionary
        for baseport in dic_baseport_mac.keys():
            if_index = dic_baseport_index[baseport]
            mac = dic_baseport_mac[baseport]
            dic_if_mac_vlan[if_index] = [mac, vlan]

    return


def insert_indexes_macs_vlans():
    """Inserts the interface indexes, mac addresses, and vlan ids
    into the table."""
    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Insert dictionary content in DB
    for index in dic_if_mac_vlan.keys():
 
        insert = """
                     INSERT INTO %s (IF_INDEX, MAC, VLAN)
                     VALUES ('%s', '%s', '%s')
                 """ % (table_name,\
                        index,\
                       (dic_if_mac_vlan[index])[0],\
                       (dic_if_mac_vlan[index])[1])

        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in DB insertion: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_ipv4_addresses():
    """Populates the ipv4 address column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ipNetToMediaPhysAddress']

    arp_table = subprocess.Popen(['snmpwalk'] + arg,\
                                 stdout=subprocess.PIPE).communicate()[0]

    arp_table_list = arp_table.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse lists' items to get ip and mac addresses to insert into DB table
    for row in arp_table_list:
        string, mac = (row.split(' = STRING: '))[0:2]
        
        dot = '.'
        string = string.split('IP-MIB::ipNetToMediaPhysAddress.')
        ip = dot.join(((string[1]).split('.'))[1:5])

        update = """
                    UPDATE %s
                    SET MOST_RECENT_IPV4 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name, ip, mac)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_ipv6_addresses():
    """Populates the ipv6 address column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           '']

    arp_table = subprocess.Popen(['snmpwalk'] + arg,\
                                 stdout=subprocess.PIPE).communicate()[0]

    arp_table_list = arp_table.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse lists's items to get _ and ipv6 addresses to insert into DB table
    for row in arp_table_list:


        #### Missing OID that maps ipv6 addresses to if_index or mac address


        update = """
                    UPDATE %s
                    SET MOST_RECENT_IPV6 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name, ip, mac)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_descriptions():
    """Populates the description column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           IF_DESCRIPTION_OID]

    if_descr = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_descr_list = if_descr.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get index and description to insert into DB table
    for row in if_descr_list:

        index, descr = row.split(' = STRING: ')[0:2]
        index = index.split('.')[-1]

        if 'GigabitEthernet' in descr:
            port = descr.split('/')[-1]

            update = """
                        UPDATE %s
                        SET description = '%s', switch_port = '%s'
                        WHERE if_index = '%s'
                     """ % (table_name, descr, port, index)
        else:
            update = """
                        UPDATE %s
                        SET description = '%s'
                        WHERE if_index = '%s'
                     """ % (table_name, descr, index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()


    # Close database connection
    db.close()

    return


def update_last_detection():
    """Populates the most_recent_detection column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ifLastChange']

    if_date = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_date_list = if_date.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # most recent detection to insert into DB table
    for row in if_date_list:
        index, epoch = row.split(' = Timeticks: ')[0:2]
        index = index.split('.')[-1]
        epoch = (epoch.split(' ')[0])[1:-1]

        update = """
                    UPDATE %s
                    SET MOST_RECENT_DETECTION = '%s'
                    WHERE IF_INDEX = '%s'
                 """ % (table_name, epoch, index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_first_detection():
    """Populates the first_detection column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'INSERT OID HERE']

    if_date = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_date_list = if_date.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # most recent detection to insert into DB table
    for row in if_date_list:
        index, epoch = row.split(' = Timeticks: ')[0:2]
        index = index.split('.')[-1]
        epoch = (epoch.split(' ')[0])[1:-1]

        update = """
                    UPDATE %s
                    SET FIRST_DETECTION = '%s'
                    WHERE IF_INDEX = '%s'
                 """ % (table_name, epoch, index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def main():

    print 'Retrieving VLAN ids...'
    populate_vlans_ids()

    print 'Retrieving interface indexes, mac addresses...'
    retrieve_indexes_macs()

    print 'Inserting interface indexes, mac addresses, and vlans in',\
    table_name
    #insert_indexes_macs_vlans()

    print 'Adding known ipv4 addresses...'
    #update_ipv4_addresses()

    print 'Adding descriptions...'
    #update_descriptions()

    print 'Adding most recent detection dates...'
    #update_last_detection()

    print 'Adding first detection dates...'
    #update_first_detection()


if __name__ == '__main__':
    main()
 



#!/usr/bin/env python2
"""Usage: ./poll_switch.py

The purpose of this script is to populate and/or update a
database table with information about the devices connected 
to a switch stack Cisco 2960XR."""
import MySQLdb
import subprocess
import re

# Global dictionary of Interface Index ID => [MAC address, VLAN]
dic_if_mac_vlan = {}

# Global VLAN's IDs list
VLANS_IDS = []
    
# MIB OIDs
ARP_TABLE_OID = '.1.3.6.1.2.1.3.1.1.2'
IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'

# MIB MODULES 
VLAN_IF_TABLE_MOD = 'BRIDGE-MIB:CISCO-IF-EXTENSION-MIB:CISCO-VLAN-IFTABLE-RELATIONSHIP-MIB:IF-MIB'

# Open file with database credentials
file_name = '/db_creds.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open file with the switch SNMP credentials and the database table
# name that will store the devices connected to the switch 
file_name = '/snmp_switch.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]

# Open file with the firewall's SNMP credentials 
file_name = '/snmp_firewall.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
fversion, fsecurity, fuser, fauth_protocol, fauth_password,\
fpriv, fpriv_password, fhost = creds[0:8]

# Open file with VLAN numbers and their use
file_name = '/vlans_switch.txt'
file_object = open(file_name,'r')
lines = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

#Store them in variables
phones_vlan, admins_vlan = lines[0:2]

def populate_vlans_ids():
    """Populates a global list of the found VLANs IDs."""
    # Arguments to be used in snmpwalk
    arg = ['-m' + VLAN_IF_TABLE_MOD, '-v' + version, '-l' + security,\
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


def update_indexes_macs_vlans():
    """Updates the interface indexes, mac addresses, and vlan ids
    into the table."""
    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Insert dictionary content in DB
    for index in dic_if_mac_vlan.keys():

        mac, vlan = (dic_if_mac_vlan[index])[0:2]

        query = """
                   SELECT * FROM %s
                   WHERE mac = '%s' AND if_index = '%s' AND vlan = '%s'
                """ % (table_name,\
                       mac,\
                       index,\
                       vlan\
                      )

        row_exists = cursor.execute(query)

        # If exact instance(device) exists, continue with next
        if row_exists:
            continue

        # Now let's determine if this is the first time this MAC has
        # been seen or if this time the MAC is showing up on a VLAN 
        # that is not in its allowed vlan list
        detect_suspicious_devices(index, mac, vlan, cursor)

        # In any case, just add new instance to table
        query = """
                   INSERT INTO %s (IF_INDEX, MAC, VLAN)
                   VALUES ('%s', '%s', '%s')
                """ % (table_name,\
                       index,\
                       mac,\
                       vlan
                      )

        try:
            cursor.execute(query)
            db.commit()

        except:
            print 'Error in DB insertion: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def detect_suspicious_devices(index, mac, vlan, cursor):
    """Detects suspicious devices and triggers alerts if necessary."""

    # First, determine if this is the first time this MAC has
    # been seen, otherwise, detect if the MAC is showing up on a VLAN 
    # that is not in its allowed vlan list
    query = """
                SELECT * FROM %s
                WHERE mac = '%s'
            """ % (table_name,\
                   mac)

    row_exists = cursor.execute(query)

    if not row_exists:
        #Alert
        print "New MAC appeared on the network"

    else: # If the MAC existed, it might be on more than one VLAN now

        # Check if this device is allowed on this new VLAN
        query = """
                    SELECT allowed_vlan_list FROM %s
                    WHERE mac = '%s'
                """ % (table_name,\
                       mac)

        cursor.execute(query)
        allowed = False

        for results in cursor:
            for item in results:
                if vlan in item:
                    allowed = True

        if not allowed:
            #Alert
            print "MAC appears on a VLAN that is not in its allowed VLANs list"

    # Second, determine if the MAC appears on a VLAN known to be for phones
    # and does not have a prefix that maps to Cisco
    if vlan in phones_vlan:
        if "0:e1:6d:ba" not in mac and\
           "c8:0:84:aa" not in mac and\
           "2c:3e:cf:87" not in mac and\
           "6c:fa:89:94" not in mac and\
           "54:4a:0:37" not in mac:
            #Alert
            print "%s is on the phones' VLAN" % mac

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

    # Get ARP entries of devices not routed by switch
    query_firewall()

    # Detect which MACs are not in the ARP entry and alert
    detect_no_ARP_entry()

    return


def update_ipv6_addresses():
    """NOT USED CURRENTLY; ipv6 is not enabled on switch.
    Populates the ipv6 address column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ipv6NetToMediaPhysAddress']

    arp_table = subprocess.Popen(['snmpwalk'] + arg,\
                                 stdout=subprocess.PIPE).communicate()[0]

    arp_table_list = arp_table.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse lists's items to get mac and ipv6 addresses to insert into DB table
    for row in arp_table_list:

        #mac = 
        #ip =

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


def update_staff_names():
    """Populates the staff_name column of the table."""
    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ifAlias']

    if_name = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_name_list = if_name.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # staff name to insert into DB table
    for row in if_name_list:
        index, name = row.split(' = STRING: ')[0:2]
        index = index.split('.')[-1]

        update = """
                    UPDATE %s
                    SET STAFF_NAME = '%s'
                    WHERE IF_INDEX = '%s'
                 """ % (table_name, name, index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_make_model():
    """Populates the make_model column of the table."""
    # Arguments to be used in snmpwalk
    arg1 = ['-v' + version, '-m' + 'ENTITY-MIB', '-l' + security,\
           '-u' + user, '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host, 'entPhysicalModelName']

    arg2 = ['-v' + version, '-m' + 'ENTITY-MIB', '-l' + security,\
           '-u' + user, '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host, 'entPhysicalAlias']

    if_makemodel = subprocess.Popen(['snmpwalk'] + arg1,\
                                stdout=subprocess.PIPE).communicate()[0]

    alias_if = subprocess.Popen(['snmpwalk'] + arg2,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_makemodel_list = if_makemodel.splitlines()
    alias_if_list = alias_if.splitlines()

    temp_dic = {}

    for row in alias_if_list:
        left, index = row.split(' = STRING: ')[0:2]

        if index == '':
            continue

        alias = left.split('.')[-1]
        temp_dic[alias] = index

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # make/model to insert into DB table
    for row in if_makemodel_list:
        alias, make_model = row.split(' = STRING: ')[0:2]
        alias = alias.split('.')[-1]

        if alias not in temp_dic.keys():
            continue

        update = """
                    UPDATE %s
                    SET MAKE_MODEL = '%s'
                    WHERE IF_INDEX = '%s'
                 """ % (table_name, make_model, temp_dic[alias])
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in DB update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def detect_no_ARP_entry():
    """Detects and triggers an alert if a device shows up in the MAC
       table but not the ARP neighbor table; this would suggest
       that a device on the network is not talking IPv4/6, which
       should never be the case."""
    
    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    query = """
               SELECT mac, most_recent_ipv4, vlan FROM %s
            """ % (table_name)

    cursor.execute(query)

    for results in cursor:
        lst = list(results)
        
        mac = lst[0]
        ip = lst[1]
        vlan = lst[2]

        if ip == None and mac != '0:11:32:1b:65:14' and mac != '8:5b:e:5d:cf:d4':
            #Alert
            print "The MAC %s is not in the ARP neighbor table" % mac
 
    return


def query_firewall():
    """Get the ARP entries for the MAC addresses that are routed
    by the firewall. Because some of the switch devices are being 
    routed by the firewall instead of the switch, their ARP entries
    are empty from the perspective of the switch. """

    # Arguments to be used in snmpwalk
    arg = ['-v' + fversion, '-l' + fsecurity, '-u' + fuser,\
           '-a' + fauth_protocol, '-A' + fauth_password,\
           '-x' + fpriv, '-X' + fpriv_password, fhost,\
           'ipNetToMediaPhysAddress']

    ip_mac = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    ip_mac_list = ip_mac.splitlines()

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()
 
    for ln in ip_mac_list:
        left, mac = ln.split(' = STRING: ')[0:2]
        dot = '.'
        ip = dot.join(left.split('.')[2:6])

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

    return


def main():
    """Main program."""
    # The following DROP and CREATE sql commands should be 
    # commented when the project testing is completed.

    #'''

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    drop = """
              DROP TABLE IF EXISTS %s
           """ % (table_name)

    print 'Dropping previous %s table...' % (table_name)
    cursor.execute(drop)
    db.commit()


    create = """
                CREATE TABLE %s (
                                 if_index INT(5) NOT NULL,
                                 mac VARCHAR(50) NOT NULL, 
                                 vlan VARCHAR(5) NOT NULL,
                                 staff_name VARCHAR(120),
                                 switch_port INT(5), 
                                 make_model VARCHAR(120),
                                 description VARCHAR(120),
                                 most_recent_detection VARCHAR(15),
                                 allowed_vlan_list VARCHAR(120),
                                 most_recent_ipv4 VARCHAR(50),
                                 most_recent_ipv6 VARCHAR(50),
                                 PRIMARY KEY(if_index, mac, vlan)
                                 )
            """ % (table_name)

    print 'Creating table %s...' % (table_name)
    cursor.execute(create)
    db.commit()

    # Close database connection
    db.close()

    #'''

    print 'Retrieving VLAN ids...'
    populate_vlans_ids()

    print 'Retrieving interface indexes, mac addresses...'
    retrieve_indexes_macs()

    print 'Updating or inserting interface indexes, mac addresses, and vlans in %s...'\
    % (table_name)
    update_indexes_macs_vlans()

    print 'Adding known ipv4 addresses...'
    update_ipv4_addresses()

    print 'Adding descriptions...'
    update_descriptions()

    print 'Adding most recent detection dates...'
    update_last_detection()

    print 'Adding staff names...'
    update_staff_names()

    print 'Adding make/model...'
    update_make_model()


if __name__ == '__main__':
    main()
 

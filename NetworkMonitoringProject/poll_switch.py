#!/usr/bin/env python2
"""Usage: ./poll_switch.py

The purpose of this script is to populate and/or update a
database table with information about the devices connected 
to a switch stack Cisco 2960XR."""
import MySQLdb
import subprocess
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import *

# Global list of triples [Interface Index ID, MAC address, VLAN]
list_if_mac_vlan = []

# Global VLAN's IDs list
VLANS_IDS = []
    
# MIB OIDs
ARP_TABLE_OID = '.1.3.6.1.2.1.3.1.1.2'
IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'

# MIB MODULES 
VLAN_IF_TABLE_MOD = 'BRIDGE-MIB:CISCO-IF-EXTENSION-MIB:CISCO-VLAN-IFTABLE-RELATIONSHIP-MIB:IF-MIB'

# Open file with database credentials
file_name = '/var/www/vhosts/netwatch.mivamerchant.net/private/db_creds.txt'
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
    """Populates the global list of interface indexes and their\
    respective MAC addresses and VLANs."""

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

        # Populate the global list_if_mac_vlan
        for baseport in dic_baseport_mac.keys():
            if baseport not in dic_baseport_index:
                continue
            if_index = dic_baseport_index[baseport]
            mac = dic_baseport_mac[baseport]
            list_if_mac_vlan.append([if_index, mac, vlan])

    print '-> Number of found devices:',len(list_if_mac_vlan)

    return


def update_indexes_macs_vlans():
    """Updates the interface indexes, mac addresses, and vlan ids
    into the table."""

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Insert list_if_mac_vlan content in table
    for item in list_if_mac_vlan:
        index, mac, vlan = item[0:3]

        query = """
                   SELECT * FROM %s
                   WHERE mac = '%s' AND if_index = '%s' AND vlan = '%s'
                """ % (table_name,\
                       mac,\
                       index,\
                       vlan\
                      )

        row_exists = cursor.execute(query)

        dat = datetime.now()

        # If exact row exists, update last_seen column and continue
        if row_exists:
            update = """
                        UPDATE %s
                        SET last_seen = '%s'
                        WHERE mac = '%s' AND if_index = '%s' AND vlan = '%s'
                     """ % (table_name,\
                            dat,\
                            mac,\
                            index,\
                            vlan\
                           )

            try:
                cursor.execute(update)
                db.commit()

            except:
                print 'Error in table update: ', cursor._last_executed
                db.rollback()

            continue

        # Otherwise, just add new device to table
        insert = """
                    INSERT INTO %s (if_index, mac, vlan, is_new, last_seen)
                    VALUES ('%s', '%s', '%s', 'Y', '%s')
                 """ % (table_name,\
                        index,\
                        mac,\
                        vlan,\
                        dat
                       )

        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in table insertion: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_ipv4_addresses():
    """Populates the ipv4 address column of the table."""

    # First, get ARP entries of devices not routed by switch
    query_firewall()

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
                    SET most_recent_ipv4 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac)
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

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
                    SET most_recent_ipv6 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

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
                    SET most_recent_ipv4 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

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
                     """ % (table_name,\
                            descr,\
                            port,\
                            index)
        else:
            update = """
                        UPDATE %s
                        SET description = '%s'
                        WHERE if_index = '%s'
                     """ % (table_name,\
                            descr,\
                            index)
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
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
        index, ticks = row.split(' = Timeticks: ')[0:2]
        index = index.split('.')[-1]
        ticks = int((ticks.split(' ')[0])[1:-1])
        seconds = ticks/100
        delta = timedelta(seconds=seconds)
        today = datetime.now()
        dat = today - delta

        update = """
                    UPDATE %s
                    SET most_recent_detection = '%s'
                    WHERE if_index = '%s'
                 """ % (table_name,\
                        dat,\
                        index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def update_staff_name():
    """On the new entries of the table, populates the staff_name
       column."""

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
                    SET staff_name = '%s'
                    WHERE if_index = '%s' AND is_new = 'Y'
                 """ % (table_name,\
                        name,\
                        index)

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
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
                    SET make_model = '%s'
                    WHERE if_index = '%s'
                 """ % (table_name,\
                        make_model,\
                        temp_dic[alias]\
                       )
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    # Close database connection
    db.close()

    return


def detect_suspicious_devices():
    """Detects suspicious devices and triggers alerts if necessary.
       Suspicious devices might be: new devices, devices that are 
       on the phones VLAN but are not phones, and devices that do
       not have an IP address."""

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Get new devices in table
    query = """
                SELECT mac, vlan, most_recent_ipv4 
                FROM %s
                WHERE is_new = 'Y'
            """ % (table_name)

    cursor.execute(query)
    
    for result in cursor:
        mac = result[0]
        vlan = result[1]
        ipv4 = result[2]
        message = "Device " + mac + " appeared on the network. "
        print 'New device:', mac

        # Check if this device is allowed on this VLAN
        query = """
                    SELECT allowed_vlan_list 
                    FROM %s
                    WHERE mac = '%s'
                """ % (table_name, mac)

        cursor.execute(query)
        allowed = False

        for results in cursor:
            for item in results:
                if type(item) is list:
                    if vlan in item:
                        allowed = True

        if not allowed:
            message += "Device is on VLAN that is not in its allowed VLANs list. "
            print 'Device is on VLAN that is not in its allowed VLANs list'

        # Determine if the MAC appears on a VLAN known to be for phones
        # and does not have a prefix that maps to Cisco
        if vlan in phones_vlan:
            if "0:e1:6d:ba" not in mac and\
               "c8:0:84:aa" not in mac and\
               "2c:3e:cf:87" not in mac and\
               "6c:fa:89:94" not in mac and\
               "54:4a:0:37" not in mac:
                message += "Device is on the phones VLAN. "
                print 'Device is on the phones VLAN'

        # If the device does not have an IP address, it may suggest
        # that a device on the network is not talking IPv4/6, which
        # should never be the case
        if ip == None:
            message += "Device is not in the ARP neighbor table. "
            print 'MAC address %s is not in the ARP neighbor table' % mac

        notice_email(message)

    return


def notice_email(msg):
    """Sends an email alert."""

    # Initialize SMTP server
    server = smtplib.SMTP('localhost',25)
    server.starttls()

    f = 'alerts@netwatch.mivamerchant.net'
    t = 'pwilthew@miva.com'

    container = MIMEMultipart('alternative')
    container['Subject'] = 'Network Alert: %s' % table_name
    container['From'] = f
    container['To'] = t

    extra = "Visit netwatch.mivamerchant.net/phpMyEdit/%s.php and edit the \
             Allowed VLAN List field for the new device; i.e: '120, 230'\n" % table_name
    text = msg + extra
    
    html = """\
              <html>
                <head></head>
                <body>
                    <p>%s</p>
                    <p>Visit <a href="netwatch.mivamerchant.net/phpMyEdit/%s.php">this \
                    site</a> and edit the Allowed VLAN List field for the new device; \
                    i.e: '120, 230'\n </p>
                </body>
              </html>
           """ % (msg, table_name)

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    container.attach(part1)
    container.attach(part2)

    server.sendmail(f, t, container.as_string())
    server.quit()


def main():
    """Main program."""

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Query to determine if table_name exists
    check = """
               SHOW TABLES LIKE '%s'
            """ % (table_name)

    # Boolean variable that holds True if a table_name exists
    table_existed = cursor.execute(check)
    
    if not table_existed:

        # Query to create a new table that will contain all the devices
        # on the network. It will be called table_name
        create = """
                    CREATE TABLE %s   (
                                      if_index INT(5) NOT NULL,
                                      mac VARCHAR(50) NOT NULL, 
                                      vlan VARCHAR(5) NOT NULL,
                                      staff_name VARCHAR(120),
                                      switch_port INT(5), 
                                      make_model VARCHAR(120),
                                      description VARCHAR(120),
                                      most_recent_detection TIMESTAMP,
                                      allowed_vlan_list VARCHAR(120),
                                      most_recent_ipv4 VARCHAR(50),
                                      most_recent_ipv6 VARCHAR(50),
                                      is_new VARCHAR(1),
                                      last_seen TIMESTAMP,
                                      PRIMARY KEY(if_index, mac, vlan),
                                      CONSTRAINT uniq UNIQUE(if_index, mac, vlan)
                                      )
                 """ % (table_name)

        print '-> Creating table %s...' % (table_name)
        cursor.execute(create)
        db.commit()

    print '-> Retrieving VLAN ids...'
    populate_vlans_ids()

    print '-> Retrieving interface indexes, mac addresses...'
    retrieve_indexes_macs()

    print '-> Updating or inserting interface indexes, mac addresses, and vlans...'
    update_indexes_macs_vlans()

    print '-> Adding known ipv4 addresses...'
    update_ipv4_addresses()

    print '-> Adding descriptions...'
    update_descriptions()

    print '-> Adding most recent detection dates...'
    update_last_detection()

    print '-> Adding staff names on new devices only, if found...'
    update_staff_name()

    print '-> Adding make/model...'
    update_make_model()

    # The following function will make queries on table_name 
    # to detect new and/or suspicius devices on the network
    print '-> Detecting new and/or suspicious devices...'
    detect_suspicious_devices()
    
    # As all the new and/or suspicious devices were reported, make them
    # not new to avoid reporting them again on the next run

    # Query to set column is_new to 'N'
    set_not_new = """
                     UPDATE %s
                     SET is_new = 'N'
                  """ % (table_name)

    try:
        cursor.execute(set_not_new)
        db.commit()

    except:
        print "Error in table update:", cursor._last_executed
        db.rollback()   

    db.close()


if __name__ == '__main__':
    main()


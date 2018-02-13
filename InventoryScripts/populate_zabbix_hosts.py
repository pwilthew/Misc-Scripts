#!/usr/bin/env python2

"""Populate the zabbix_hosts database table."""

from pyzabbix import ZabbixAPI

import json

import MySQLdb



def main():
    """Obtain monitored hosts in Zabbix and insert their id
    and name into a database table."""
    # DB connection
    db, cursor = get_db_and_cursor()

    # Zabbix connection
    # Note that the following request will not work if the
    # zabbix server is not expecting traffic from this host
    file_obj = open('source/zabbix_creds.txt', 'r')
    username, passwd = file_obj.read().splitlines()
    zapi = ZabbixAPI(url='https://zabbix.mivamerchant.net',
                     user=username,
                     password=passwd)

    # Get all monitored hosts from Zabbix
    result1 = zapi.host.get(monitored_hosts=1, output='extend')

    # Make a list of tuples (hostids, hostnames)
    host_names_ids = [(item['hostid'], item['host']) for item in result1]

    # Insert tuples in table
    for host_tuple in host_names_ids:
        if not valid_host(host_tuple[1]):
            continue

        insert = """
                    INSERT INTO zabbix_hosts (id, hostname) 
                    VALUES ('%s', '%s')
                    ON DUPLICATE KEY UPDATE hostname='%s'
                 """ % (host_tuple[0], host_tuple[1], host_tuple[1])
        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in table insert:', cursor._last_executed
            db.rollback()

    return


def valid_host(hostname):
    """Returns True if hostname ends with .com, .net, .local"""
    suffix = hostname[-3:]
    if "esx-tpa-l3-ucs2" in hostname:
        return False
    elif "pwr-l3-tpa-" in hostname:
        return False
    elif "Authorize" in hostname:
        return False
    elif suffix == "com" or suffix == "net" or suffix == "local":
        return True
    return False


def get_db_and_cursor():
    """Return a database and cursor objects for inventory
    database."""
    file_obj = open("/home/inventory/HostsInventory/source/db_creds.txt", "r")
    username, db_name, password = file_obj.read().splitlines()
    db = MySQLdb.connect(user=username, db=db_name, passwd=password)
    cursor = db.cursor()

    return db, cursor


if __name__ == '__main__':
    main()




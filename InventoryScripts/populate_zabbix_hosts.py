#!/usr/bin/python3.6

"""Populate the zabbix_hosts database table."""
import logging
logger = logging.getLogger(__name__)

import config

import json

import pymysql

import sys

from aux_functions import get_db_and_cursor

from pyzabbix import ZabbixAPI



def main():
    """Obtain monitored hosts in Zabbix and insert their id
    and name into a database table."""
    # DB connection
    db, cursor = get_db_and_cursor()

    # Zabbix connection
    # Note that the following request will not work if the
    # zabbix server is not expecting traffic from this host
    server, user, passw = config.ZABBIX_CREDS

    try:
        zapi = ZabbixAPI(server=server)
        zapi.login(user=user, password=passw)
    except e:
        logger.error("Could not connect or authenticate to Zabbix server.")
        return

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

        except e:
            logger.error("%s: %s" % (host_tuple[1], str(e)))
            db.rollback()

    return


def valid_host(hostname):
    """Returns True if hostname ends with .com, .net, .local"""
    suffix = hostname[-3:]
    if suffix == "com" or suffix == "net" or suffix == "local":
        return True
    return False


if __name__ == '__main__':
    main()

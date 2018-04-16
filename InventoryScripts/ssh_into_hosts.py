#!/usr/bin/python3.6

"""Obtain the following data from each host after
establishing a remote connection:

    - Network Interfaces
    - Total RAM
    - Total Cores
    - Is it a Virtual Machine?
    - Disk Sizes

Stored the obtained data in the following database
tables:

    - interfaces
    - total_ram
    - total_cores
    - virtualized
    - disk_size """
import logging
logger = logging.getLogger(__name__)

import config

import json

import pymysql

import os

import re

import sys

import subprocess

import threading

import time

from collections import defaultdict

from aux_functions import get_db_and_cursor



def get_and_store_info(server, dic):
    """For a given server, get its interfaces, total ram, 
    total cores, VM or not, and disk sizes as an output 
    from get_info_through_ssh(). Store each item in a
    dictionary after properly parsing it."""
    ipaddr, ram, cores, virtual, disksize = get_info_through_ssh(server)

    ipaddr = parse_ipaddr(ipaddr)
    ram = parse_ram(ram)
    cores = parse_cores(cores)
    virtual = parse_virtual(virtual)
    disksize = parse_disksize(disksize)

    dic[server] = {'ipaddr':ipaddr,
                   'ram':ram,
                   'cores':cores,
                   'virtual':virtual,
                   'disksize':disksize
                  }

    return


def get_info_through_ssh(server):
    """Given a server hostname, establish a secure shell
    connection with it, and execute the necessary bash
    commands to return its network interfaces, total ram,
    total cores, VM or not, and disk sizes."""
    commands = (
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin:/sbin;"
        "echo '***';"
        "ip addr;"
        "echo '***';"
        "cat /proc/meminfo | grep MemTotal | egrep --color='never' -o '[0-9]+';"
        "echo '***';"
        "cat /proc/cpuinfo | grep --color='never' -c processor;"
        "echo '***';"
        "cat /proc/cpuinfo | grep --color='never' -c hypervisor;"
        "echo '***';"
        "lsblk -lda"
        )

    args = ["ssh", "inventory@" + server, commands]

    ret_code, out, err = run_command(args)

    if ret_code:
        logger.warning("%s: %s" % (server, str(err).strip("\n")))
        return "", "", "", "", ""
        
    divided = [x for x in out.split("***") if x]
    return divided[0], divided[1], divided[2], divided[3], divided[4]


def parse_ipaddr(info):
    """Return a list of only the network interfaces' names
    and ip addresses given the string returned by `ip addr`.
    """
    if not info:
        return []

    ipv4_list, ipv6_list, interfaces = [], [], []

    for line in str(info).splitlines():
        if re.findall(r'inet\s', line):
            if 'scope global' in line:  # Only add scope global addresses
                ipv4_list.append(line.strip())

        if re.findall(r'inet6\s', line):
            if 'scope global' in line:  # Only add scope global addresses
                ipv6_list.append(line.strip())

    for item in ipv4_list:
        int_name = ''

        if item[-1].isdigit():
            ip = item.split(' ')[1]
            interfaces.append(ip)

    for item in ipv6_list:
        ip = item.split(' ')[1]
        interfaces.append(ip)

    return interfaces


def parse_ram(info):
    """Return the integer corresponding to the total ram in
    a server and round up to GB."""
    if not info:
        return -1

    return (-(int(info) / -1048576))


def parse_cores(info):
    """Return the integer corresponding to total cores in a
    server."""
    if not info:
        return -1

    return int(info)


def parse_virtual(info):
    """Return 1 if the output of `cat /proc/cpuinfo | grep
    -c hypervisor` is 1 or more. That is, if the word 
    hypervisor appears 1 or more times in the output of 
    `cat /proc/cpuinfo | grep -c hypervisor`."""
    if not info:
        return -1
    
    if info.isdigit():
        if int(info) > 0:
            return 1
    else:
        if int(info) > 0:
            return 1
    return 0


def parse_disksize(info):
    """Return a string containing the names of the disks
    and their sizes."""
    if not info:
        return ""

    blocks_list = info.splitlines()[1:]
    blocks_list = [b.split() for b in blocks_list]

    disks_list = []
    for b in blocks_list:
        if b[-1] == 'disk':
            disks_list.append(b)

    return ", ".join([d[0] + ": " + d[3] for d in disks_list])


def insert_list_in_table(server, interfaces, db, cursor):
    """Insert the networks interfaces' names and ip
    addresses of a given server in the database."""
    for iface in interfaces:
        insert = """REPLACE INTO interfaces (hostname, interface)
                    VALUES ('%s', '%s')
                 """ % (server, iface)
        try:
            cursor.execute(insert)
            db.commit()

        except:
            print("Error in table insert: %s" % cursor._last_executed)
            db.rollback()

    return


def insert_value_in_table(server, table, db, cursor, column, value):
    """Insert the pair (server, value) into the given
    table."""
    insert = """REPLACE INTO %s (hostname, %s)
                VALUES ('%s', '%s')
             """ % (table, column, server, value)
    try:
        cursor.execute(insert)
        db.commit()

    except e:
        logger.error("%s: %s" % (server, str(e)))
        db.rollback()

    return


def run_command(cmd_args):
    """Wrapper to run a command in subprocess."""
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
    out, err = proc.communicate()
    return proc.returncode, out, err

    
def main():
    """Establish a secure shell connection with hosts in the
    ipa_hosts database table to get information from each
    host and insert it in its respective database tables."""
    # DB connection
    servers_dic = {}

    # DB connection
    db, cursor = get_db_and_cursor()

    # Obtain a list of tuples in the form: (hostname,)
    query = """SELECT * FROM ipa_hosts"""
    cursor.execute(query)

    
    # Create a list of hostnames
    servers = [x[0] for x in cursor.fetchall()]
    # Create a list of threads
    threads = [threading.Thread(target=get_and_store_info, 
                                args=(s, servers_dic)) for s in servers]

    # Execute all threads
    for thread in threads:
        thread.start()

    # Join all threads
    for thread in threads:
        thread.join()

    # Insert dictionary values into tables
    for server in servers_dic:
        info_server = servers_dic[server]
        insert_list_in_table(server, info_server['ipaddr'], db, cursor)
        insert_value_in_table(server, 'total_ram', db, cursor, 'ram', 
                                                        info_server['ram'])
        insert_value_in_table(server, 'total_cores', db, cursor, 'cores', 
                                                        info_server['cores'])
        insert_value_in_table(server, 'virtualized', db, cursor, 'virtual', 
                                                        info_server['virtual'])
        insert_value_in_table(server, 'disk_size', db, cursor, 'disksize', 
                                                        info_server['disksize'])

    return
    

if __name__ == '__main__':
    main()

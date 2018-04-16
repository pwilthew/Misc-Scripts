#!/usr/bin/env python2.7
"""Usage: ./create_rogue_report.py

    As per requirement 11 in PCI, we have to implement processes to test
    for the presence of wireless access points and detect and identify all
    authorized and unathorized wireless access points on a quarterly basis.

    The purpose of this script is to obtain the output of daily rogue scans
    to verify that authorized and unauthorized wireless access points
    are identified.
"""
import time

import paramiko 

import sys

import os

from htmlify import htmlify



ROOT = "/root/rogue_report/"

def disable_paging(conn):
    """Execute command to disable paging in the WAC shell.
        Input:
            conn: A connection object created with paramiko.
        Output:
            Response message, if any, from the WAC.
    """
    conn.send("config paging disable\n")
    time.sleep(1)
    return conn.recv(1000)


def get_file_names(timestamp):
    """Generate the names of the files to be written based
    on the date. Also, create the monthly directories for the
    new files if they have not been created.
        Input:
            timestamp: The current timestamp in string format.
        Output: 
            log_name: Full path to the file to be used as plaintext log.
            html_name: Full path to the file to be used as html log.
    """
    if not ROOT.endswith("/"):
        sys.exit("Error: ROOT global variable has to end with '/'")

    date = timestamp.split(":")[0]
    month, _, year = date.split("-")

    month_dir = year + "-" + month
    html_dir = "html/" + month_dir + "/"
    logs_dir = "logs/" + month_dir + "/"

    if not os.path.exists(ROOT + logs_dir):
        os.mkdir(ROOT + logs_dir)

    if not os.path.exists(ROOT + html_dir):
        os.mkdir(ROOT + html_dir)

    log_name = ROOT + logs_dir + timestamp + ".log"
    html_name = ROOT + html_dir + timestamp + ".html"

    return log_name, html_name


def create_log():
    """Get needed information from the Cisco WAC and log it
    in both plaintext and html formats.
        Output: 
            0 if successful; 1 otherwise.
    """
    timestamp = str(time.strftime("%m-%d-%Y:%H:%M:%S"))
    log_name, html_name = get_file_names(timestamp)

    # Wireless Controller IP, username, and password
    ip = "1.1.1.1"          # Hidden
    user = "user\n"         # Hidden
    password = "password\n" # Hidden

    # Instance of SSHClient object
    remote_conn = paramiko.SSHClient()

    # Automatically add untrusted hosts
    remote_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Initiate SSH connection
    try:
        remote_conn.connect(
                        ip, 
                        username=user, 
                        password=password, 
                        look_for_keys=False, 
                        allow_agent=False)
    except:
        print (
            "Connection cannot be established."
            "Make sure the IP is correct and that the host is reachable."
        )
        return 1

    # Establish an interactive session
    try:
        remote_conn = remote_conn.invoke_shell()
    except:
        print "Error invoking shell"
        return 1

    try:
        # Send username
        remote_conn.send(user)
    except:
        print "Socket might be closed"
        return 1

    time.sleep(1)

    try:
        # Send password
        remote_conn.send(password)
    except:
        print "Socket might be closed"
        return 1

    time.sleep(1)

    disable_paging(remote_conn)
 
    remote_conn.send("show rogue ap summary ssid extended channel\n")

    time.sleep(1)
    
    # Log response in plaintext file
    with open(log_name, "w") as log_file:
        log_file.write(timestamp + "\n")
        log_file.write(remote_conn.recv(20000))

    time.sleep(1)

    # Generate html content from the plaintext in html file
    htmlify(log_name, html_name)

    return 0


if __name__ == '__main__':

    error = create_log()
    iteration = 0

    # If create_log is unsuccessful the first time,
    # then run a maximum of 20 times every 2 minutes
    # and stop only when create_log is successful
    while error and iteration <= 20:
        iteration += 1
        time.sleep(120)
        error = create_log()
#!/usr/bin/python
"""Usage: sudo ./portchecker-without-netstat.py

The purpose of this script is to determine if there are any unexpected 
running applications that have ports open for listening. Its goal is to
detect if the machine has been compromised."""
import socket
import struct
import subprocess
import re
import syslog
import base64
import os
#
# Update FILE_NAME with the name of the csv file containing every 
# expected:
#
# Process Name, Port, Protocol, Owner, Should listen to public IPs = y/n, 
# Should listen to localhost = y/n.
#
# Each line of FILE_NAME should have the following format: 
#
#   port,TCP/UDP,process_name,owner,public,localhost
#
# Example:
#
#   80,TCP,apache,root,y,y
#
FILE_NAME = 'netports.csv'

# pids will contain a list of the pid directories under /proc/
pids = filter(lambda x: x.isdigit() and os.path.isdir('/proc/'+x),
              os.listdir('/proc/'))

# The following dictionaries get their keys and values from FILE_NAME
proc_users_dic = {}
proc_port_prot_dic = {}
proc_ip_dic = {}

# The following block creates a dictionary of 
# {process_name: (owners)}
# i.e.: 'nginx': ('nginx', 'root')
file_object = open(FILE_NAME, 'r')

for ln in file_object.readlines():
    _, _, process_name, owner = ln.split(',')[:4]

    pair = {process_name: (owner,)}

    if process_name in proc_users_dic:
        if owner not in proc_users_dic[process_name]:
            tmp = proc_users_dic[process_name]
            tmp = tmp + (owner,)
            proc_users_dic[process_name] = tmp
    else:
            proc_users_dic.update(pair)

# The following block creates a dictionary of 
# {process_name: [(port,protocol)]}
# i.e.: 'nginx': [('80', 'TCP'), ('443', 'TCP')]
file_object = open(FILE_NAME, 'r')

for ln in file_object.readlines():
    port, protocol, process_name = ln.split(',')[:3]

    port_tuple = (port,protocol)
    pair = {process_name: [port_tuple]}

    if process_name in proc_port_prot_dic:
        if port_tuple not in proc_port_prot_dic[process_name]:
            proc_port_prot_dic[process_name].append(port_tuple)
    else:
        proc_port_prot_dic.update(pair)

# The following block creates a dictionary of
# {process_name: (public,localhost)}
# i.e.: 'named': [('y', 'y'), ('n', 'y')]
file_object = open(FILE_NAME, 'r')

for ln in file_object.readlines():
    _, _, process_name, _, public, localhost = ln.split(',')[:6]

    localhost = localhost.strip('\r\n')

    public_local_tuple = (public,localhost)
    pair = {process_name: [public_local_tuple]}

    if process_name in proc_ip_dic:
        if public_local_tuple not in proc_ip_dic[process_name]:
            proc_ip_dic[process_name].append(public_local_tuple)
    else:
        proc_ip_dic.update(pair)

file_object.close()


def get_sockets(protocol):
    """Returns output of 'cat /proc/net/tcp', 'cat /proc/net/udp',
                         'cat /proc/net/tcp6, 'cat /proc/net/udp6'."""
    if protocol not in ['tcp', 'udp', 'tcp6', 'udp6']:
        print "Error: get_sockets() input can only be 'tcp' or 'udp'"
        exit()

    arg = ['/proc/net/' + protocol]

    output = subprocess.Popen(['cat'] + arg, 
                            stdout=subprocess.PIPE).communicate()[0]

    list_of_lines = output.splitlines()[1:]

    list_ = []
    protocol = protocol.upper()

    if '6' in protocol:
        protocol = protocol[:-1]  # Removes the 6 from the protocol

    for ln in list_of_lines: # From list of lines to list of lists
        sub_list = [protocol,] 
        sub_list += re.split('\s+', ln)
        list_.append(sub_list)

    return list_ 


def format_list(input_list):
    """Receives a list of lines, each corresponding to a socket,
    and returns a list of processes (where each process is 
    represented as a list)."""
    list_ = []

    for sub_list in input_list:

        while '' in sub_list:
            sub_list.remove('')

        if ('0A' not in sub_list[4]) and ('07' not in sub_list[4]):
            continue

        sub_list.remove(sub_list[1]) # Removes sl (number of line)
        sub_list.remove(sub_list[4]) # Removes tx_queue:rx_queue
        sub_list.remove(sub_list[4]) # Removes tr:tm->when
        sub_list.remove(sub_list[4]) # Removes retrnsmt
        sub_list.remove(sub_list[5]) # Removes timeout
        sub_list.remove(sub_list[3]) # Removes state

        # Save port for later appending to sub_list
        port = int(sub_list[1].split(':')[1], 16)

        # Translate ip addresses sub_list[1] and sub_list[2] 
        ip = sub_list[1].split(':')[0]
        sub_list[1] = translate_ip(ip)

        ip = sub_list[2].split(':')[0]
        sub_list[2] = translate_ip(ip)

        # Values of uid and inode needed for next function calls
        uid = sub_list[3]
        inode = sub_list[4]

        # Completing sub_list with process name, port, and owner username
        sub_list[3] = get_processname(inode)
        sub_list[4] = str(port)
        sub_list[5] = get_username(uid)

        sub_list = sub_list[0:6] # Ignore rest of elements on position > 5

        list_.append(sub_list)

    return list_


def translate_ip(ip):
    """Returns the standard decimal format of ip"""
    if len(ip) > 8:
        ip = base64.b16decode(ip)
        return socket.inet_ntop(socket.AF_INET6, 
                                struct.pack('<4I', *struct.unpack('>4I', ip)))

    else:
        return socket.inet_ntoa(struct.pack('<L', int(ip, 16)))


def get_username(uid):
    """Returns the username of a user given its uid"""
    arg = ['cat', '/etc/passwd']

    passwd = subprocess.Popen(arg, stdout=subprocess.PIPE).communicate()[0]

    for ln in passwd.splitlines():
        ln_list = ln.split(':')
        if uid in ln_list[2]:
            return ln_list[0]

    return '-'


def get_processname(inode):
    """"Returns the name of a process given a socket inode"""
    found = False

    for pid in pids:
        path = '/proc/' + pid + '/fd'
        arg = ['ls', '-l', path]
        file_descriptors = subprocess.Popen(arg, 
                           stdout=subprocess.PIPE,
                           stderr=None).communicate()[0]

        # Check if a socket is using the inode
        if 'socket:['+inode+']' in file_descriptors:
            found = True
            break # Stop, and use that pid for next statement

    if found:
        # Get process name from first line of /proc/<pid>/status
        path = '/proc/' + pid + '/status'
        arg = ['cat', path]
        status = subprocess.Popen(arg, stdout=subprocess.PIPE).communicate()[0]
        status = status.splitlines()
        return ((status[0].split('\t'))[-1]).strip()
    else:
        return 'process-name'


def compare_port(process):
    """Returns True if the process is using a port/protocol
    specified in the proc_port_prot_dic dictionary."""
    process_name = process[3]
    port = process[4]
    protocol = process[0].upper()

    if process_name not in proc_port_prot_dic:
        return False
 
    tuples_list = proc_port_prot_dic[process_name]
    port_tuple = (port, protocol)

    if port_tuple in tuples_list:
        return True

    # Cases when a port is not predictable but it is specified as 
    # "highport" in FILE_NAME. Example: highport,UDP,rsyslogd,root,y,y
    if len(port)>=4:
        port_tuple = ('highport',protocol)

        if port_tuple in tuples_list:
            return True
    
    return False


def compare_owner(process):
    """Returns True if the process is owned by the user specified in the 
    proc_users_dic dictionary."""
    process_name = process[3]
    owner = process[5]

    if process_name not in proc_users_dic:
        return False

    tuples_list = proc_users_dic[process_name]

    if owner in tuples_list:
        return True
    
    return False


def compare_ip(process):
    """Returns True if the process values of "public,localhost" are the
    same as the corresponding values for the process in proc_ip_dic."""
    process_name = process[3]
    local_address = process[1]

    if process_name not in proc_ip_dic:
        return False

    public_ips_listening = 'y'    
    localhost_listening = 'n'
    
    if local_address == '127.0.0.1' or local_address == '::1':
       public_ips_listening = 'n'

    if local_address == '127.0.0.1' or local_address == '::1' or \
       local_address == '0.0.0.0' or local_address == '::':
       localhost_listening = 'y'

    public_local_tuple = (public_ips_listening, localhost_listening)

    if public_local_tuple in proc_ip_dic[process_name]:
        return True

    return False


def main():
    """Checks if all TCP/UDP processes are listening through the 
    expected ports, are owned by the expected users, and are 
    accepting connections from the expected IP addresses."""
    OK = True

    print "Investigating..."
    
    sockets = get_sockets('tcp') \
            + get_sockets('tcp6') \
            + get_sockets('udp') \
            + get_sockets('udp6')

    processes_list = format_list(sockets)

    # At this point, a list within processes_list would look like:
    # ['TCP', '0.0.0.0', '0.0.0.0:*', 'mysqld', '3306', 'mysql']
    # where position 3 corresponds to the process name and 
    # position 5 to its owner

    for process in processes_list:
        protocol, local_address, _, process_name, port, owner = process[:6]

        correct_port, correct_owner, correct_ip = False, False, False

        if compare_port(process):
            correct_port = True

        if compare_owner(process):
            correct_owner = True

        if compare_ip(process):
            correct_ip = True

        if not (correct_port and correct_owner and correct_ip):
            message = 'ALERT: '
            should_log = True
        else:
            message = ''
            should_log = False

        message += 'process ' + process_name \
               + ' is using ' + protocol \
                        + ' ' + port \
             + ' with owner ' + owner \
        + ', listening from ' + local_address
        
        if should_log:
            syslog.syslog(syslog.LOG_ALERT, message)
            print message
            OK = False

    if OK:
        print "No suspicious connections found."

if __name__ == '__main__':
    main()
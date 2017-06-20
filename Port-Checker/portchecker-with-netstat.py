#!/usr/bin/python
"""Usage: sudo ./portchecker-with-netstat.py

The purpose of this script is to determine if there are any unexpected 
running applications that have ports open for listening. Its goal is to
detect if the machine has been compromised."""
import socket
import subprocess
import re
import syslog
#
# Update FILE_NAME with the name of the csv file containing every 
# expected:
#
# Process Name, Port, Protocol, Owner, Should listen to public IPs = y/n, 
# Should listen to localhost = y/n.
#
# Each line of this file should have the following format: 
#
#   port,TCP/UDP,process_name,owner,public,localhost
#
# Example:
#
#   80,TCP,apache,root,y,y
#
FILE_NAME = "netports.csv"

# The following dictionaries get their keys and values from FILE_NAME
proc_users_dic = {}
proc_port_prot_dic = {}
proc_ip_dic = {}

# The following block creates a dictionary of 
# {process_name: (owners)}
# i.e.: 'nginx': ('nginx', 'root')
file_object = open(FILE_NAME, "r")

for ln in file_object.readlines():
    _, _, process_name, owner = ln.split(",")[:4]

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
file_object = open(FILE_NAME, "r")

for ln in file_object.readlines():
    port, protocol, process_name = ln.split(",")[:3]

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
file_object = open(FILE_NAME, "r")

for ln in file_object.readlines():
    _, _, process_name, _, public, localhost = ln.split(",")[:6]

    localhost = localhost.strip('\r\n')

    public_local_tuple = (public,localhost)
    pair = {process_name: [public_local_tuple]}

    if process_name in proc_ip_dic:
        if public_local_tuple not in proc_ip_dic[process_name]:
            proc_ip_dic[process_name].append(public_local_tuple)
    else:
        proc_ip_dic.update(pair)

file_object.close()


def run_netstat():
    """Returns output of 'netstat -plunt'."""
    return subprocess.Popen(['netstat', '-plunt'], \
                            stdout=subprocess.PIPE).communicate()[0]


def into_list_of_lists(input_string):
    """Receives a multiline string and returns a list of lines excluding the
    first two (as the first two lines of the netstat output are not used)."""
    return [re.split("\s+", ln) for ln in input_string.splitlines()[2:]]


def format_list(input_list):
    """Receives a list of lines, each corresponding to a line of the
    "netstat -plunt" output, and returns a list of processes (where each 
    process is represented as a list)."""
    list_ = input_list

    for ln in list_:
        
        if '-' in ln:
            print "You have to be root to execute this script."
            exit()

        while '0' in ln:
            ln.remove('0') # Removes Recv-Q and Send-Q

        if 'LISTEN' in ln:
            ln.remove('LISTEN')

        if '' in ln:
            ln.remove('')

        if len(ln)==5:
            ln.remove(ln[4])     # Removes the word master, 
                                 # i.e. "nginx: master"

        if (ln[3])[-1]==":":
            ln[3] = (ln[3])[:-1] # Removes the ":" from "nginx:"

        ipv4 = ln[1].count(':')==1  # Checks if address is ipv4 or v6

        # Adds port number at the end of the list and removes it from the local
        # address for both ipv4 and ipv6 cases

        if ipv4:
            ln.append(ln[1].split(":")[1]) 
            ln[1] = ln[1].split(":")[0]
    
        else:
            ln.append(''.join(ln[1].split(":")[-1:]))
            ln[1] = ''.join(re.split('(\:)',ln[1])[:-1])
            ln[0] = ln[0][:-1]

    # Adds respective owners to processes
    list_ = add_owners(list_)

    return list_


def add_owners(input_list):
    """Receives a list of processes and appends the process owner to each
    of the lists."""
    processes_list = input_list

    for process in processes_list:
        process_name = process[3]
        pid = str(process_name.split("/")[0]) 
        process[3] = (process_name.split("/"))[1] # Removes pid from user

        arg = [pid]
        ps = subprocess.Popen(['ps', '-up'] + arg,
                              stdout=subprocess.PIPE).communicate()[0] 
        owner = (ps.split("\n")[1]).split(" ")[0]
        process.append(owner)

    return processes_list


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
        port_tuple = ("highport",protocol)
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

    public_ips_listening = "y"    
    localhost_listening = "n"
    
    if local_address == "127.0.0.1" or local_address == "::1:":
       public_ips_listening = "n"

    if local_address == "127.0.0.1" or local_address == "::1:" or \
       local_address == "0.0.0.0" or local_address == ":::":
       localhost_listening = "y"

    public_local_tuple = (public_ips_listening, localhost_listening)

    if public_local_tuple in proc_ip_dic[process_name]:
        return True

    return False


def main():
    """Checks if all TCP/UDP processes are listening through the expected ports, 
    are owned by the expected users, and are accepting connections from the 
    expected IP addresses."""
    netstat = run_netstat()

    # Creates a list of lists
    processes_list = into_list_of_lists(netstat)

    # Removes extra info and adds owners to each process
    processes_list = format_list(processes_list)

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
            message = "ALERT: "
            should_log = True
        else:
            message = ""
            should_log = False

        message += "process " + process_name \
               + " is using " + protocol \
                        + " " + port \
             + " with owner " + owner \
        + ", listening from " + local_address
    
        print message
        
        if should_log:
            syslog.syslog(syslog.LOG_ALERT, message)


if __name__ == "__main__":
    main()
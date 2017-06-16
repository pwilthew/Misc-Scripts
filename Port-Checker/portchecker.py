#!/usr/bin/python
"""
Usage: portchecker.py

The purpose of this script is to determine if there are any unexpected 
running applications that have ports open for listening. Its goal is to
detect if the machine has been compromised.
"""
import socket
import subprocess
import re
import syslog
#
# Update FILE_NAME with the name of the csv file containing every 
# expected:
# ProcessName, 
# Port, 
# Protocol,
# Owner, 
# ShouldListenToPublicIPs=y/n, 
# ShouldListenToLocalHost=y/n.
#
# Each Line of this file should have the following format: 
#
#	Port,TCP/UDP,ProcessName,Owner,Public?,Localhost?
#
# Example:
#
#	80,TCP,apache,root,y,y
#
FILE_NAME = "netports.csv"

# The following dictionaries get their keys and values from
# FILE_NAME
proc_users_dic = {}
proc_port_prot_dic = {}
proc_ip_dic = {}

# The following block creates a dictionary of 
# {ProcessName: Owner} 
FileObject = open(FILE_NAME, "r")

for Line in FileObject.readlines():
        ProcessName = Line.split(",")[2]
        Owner = Line.split(",")[3]
        dic2 = {ProcessName: (Owner)}

        if proc_users_dic.has_key(ProcessName):
                if (Owner not in proc_users_dic[ProcessName]):
                        temp = proc_users_dic[ProcessName]
                        temp = temp + (Owner)
                        proc_users_dic[ProcessName] = temp
        else:
                proc_users_dic.update(dic2)

# The following block creates a dictionary of 
# {ProcessName: [(Port,Protocol)]} 
FileObject = open(FILE_NAME, "r")

for Line in FileObject.readlines():
        ProcessName = Line.split(",")[2]
        Port = Line.split(",")[0]
        Protocol = Line.split(",")[1]

        PortTuple = (Port,Protocol)

        dic2 = {ProcessName: [PortTuple]}

        if proc_port_prot_dic.has_key(ProcessName):
		if (PortTuple not in proc_port_prot_dic[ProcessName]):
                        proc_port_prot_dic[ProcessName].append(PortTuple)
        else:
                proc_port_prot_dic.update(dic2)

# The following block creates a dictionary of
# {ProcessName: (Public,Localhost)}
FileObject = open(FILE_NAME, "r")

for Line in FileObject.readlines():
	ProcessName = Line.split(",")[2]
	public = Line.split(",")[4]
	localhost = Line.split(",")[5]
	localhost = localhost.strip('\r\n')

	public_local = (public,localhost)
	
	dic2 = {ProcessName: [public_local]}

	if proc_ip_dic.has_key(ProcessName):
		if public_local not in proc_ip_dic[ProcessName]:
			proc_ip_dic[ProcessName].append(public_local)
	else:
		proc_ip_dic.update(dic2)

FileObject.close()


def run_netstat():
	"""Returns the output of 'netstat -plunt'.
	"""

	return subprocess.Popen(['netstat', '-plunt'], \
	       stdout=subprocess.PIPE).communicate()[0]


def into_list_of_lists(StringInput):
	"""Receives a multiLine string and returns a list of lines excluding
	the first two.
	"""

	return [re.split("\s+", Line) for Line in StringInput.splitlines()[2:]]


def format_list(List):
	"""Receives a list of lines, each corresponding to a line of 
	"netstat -plunt" output and returns a list of processes (where each 
	process is a list).
	"""

	for Line in List:
		Line.remove(Line[1])
		Line.remove(Line[1])

		if len(Line)>5:
			Line.remove(Line[3]) # Removes the word LISTEN

		if len(Line)==6:
			Line.remove(Line[4])	# Removes the word master, 
						# i.e. "nginx: master"
		if (Line[3])[-1]==":":
			Line[3] = (Line[3])[:-1] # Removes the ":" from "nginx:"

		del Line[4]  # Removes an empty string from the list

		ipv4 = Line[1].count(':')==1  # Checks if address is ipv4 or v6

		# Adds port number at the end of the list and removes it from the local address
		# for both ipv4 and ipv6 cases
		if ipv4:
			Line.append(Line[1].split(":")[1]) 
			Line[1] = Line[1].split(":")[0]
	
		else:
			Line.append(''.join(Line[1].split(":")[-1:]))
			Line[1] = ''.join(re.split('(\:)',Line[1])[:-1])
			Line[0] = Line[0][:-1]

	# Adds respective owners to processes
	List = add_owners(List)

	return List


def compare_port(Process):
	"""Returns true if the process is using a Port/Protocol
	specified in the proc_port_prot_dic dictionary.
	"""

	ProcessName = Process[3]
	Port = Process[4]
	Protocol = Process[0].upper()

	if ProcessName not in proc_port_prot_dic:
		return False
 
	TuplesList = proc_port_prot_dic[ProcessName]
	PortTuple = (Port, Protocol)

	if PortTuple in TuplesList:
		return True

	# Cases when a port is not predictable but it is specified as 
	# "highport" in FILE_NAME. Example: highport,UDP,rsyslogd,root,y,y
	if len(Port)>=4:
		PortTuple = ("highport",Protocol)
		if PortTuple in TuplesList:
			return True
	
	return False


def compare_owner(Process):
	"""Returns true if the process is owned by the user specified in the 
	proc_users_dic dictionary.
	"""

	ProcessName = Process[3]
	Owner = Process[5]

	if ProcessName not in proc_users_dic:
		return False

	TuplesList = proc_users_dic[ProcessName]

	if Owner in TuplesList:
		return True
	
	return False


def add_owners(ProcessesList):
	"""Receives a list of processes and appends the process owner to each
	of the lists.
	"""

	for Process in ProcessesList:
		ProcessName = Process[3]
		Pid = str(ProcessName.split("/")[0])
		Process[3] = (ProcessName.split("/"))[1] # Removes PID from the process name
		Arg = [Pid]
		Ps = subprocess.Popen(['ps', '-up'] + Arg, \
		     stdout=subprocess.PIPE).communicate()[0]	# Gets owner of that PID
		Owner = (Ps.split("\n")[1]).split(" ")[0]
		Process.append(Owner)

	return ProcessesList


def compare_ip(Process):
	"""Returns true if the process values of "Public?,Localhost?" are the
	same as the corresponding values for the process in proc_ip_dic.
	"""

	ProcessName = Process[3]
	LocalAddress = Process[1]

	PublicIPsListening = "y"	
	LocalhostListening = "n"
	
	if LocalAddress == "127.0.0.1" or LocalAddress == "::1:":
		PublicIPsListening = "n"

	if LocalAddress == "127.0.0.1" or LocalAddress == "::1:" or \
	   LocalAddress == "0.0.0.0" or LocalAddress == ":::":
		LocalhostListening = "y"

	PublicLocalTuple = (PublicIPsListening, LocalhostListening)

	if PublicLocalTuple in proc_ip_dic[ProcessName]:
		return True

	return False


def main():
	"""Checks if all TCP/UDP processes are listening through the expected ports, 
	are owned by the expected users, and are accepting connections from the 
	expected IP addresses.
	"""

	Netstat = run_netstat()

	# Creates a list of lists
	ProcessesList = into_list_of_lists(Netstat)

        # Removes extra info and adds owners to each process
        ProcessesList = format_list(ProcessesList)

	# At this point, a list within ProcessesList would look like:
	# ['TCP', '0.0.0.0', '0.0.0.0:*', 'mysqld', '3306', 'mysql']
	# where position 3 corresponds to the process name and 
	# position 5 to its owner

	for Process in ProcessesList:
		Protocol, LocalAddress, ProcessName, Port, Owner = \
		Process[0], Process[1], Process[3], Process[4], Process[5]

		CorrectPort, CorrectOwner, CorrectIP = False, False, False

		if compare_port(Process):
			CorrectPort = True

		if compare_owner(Process):
			CorrectOwner = True

		if compare_ip(Process):
			CorrectIP = True

		if not (CorrectPort and CorrectOwner and CorrectIP):
			Message = "ALERT: "
			ShouldLog = True
		else:
			Message = ""
			ShouldLog = False

		Message += "Process " + ProcessName \
		       + " is using " + Protocol \
				+ " " + Port \
		     + " with owner " + Owner \
    + ", accepting connections from " + LocalAddress
		
		#print Message
	
		if ShouldLog:
			syslog.syslog(syslog.LOG_ALERT, Message)

if __name__ == "__main__":
	main()


#!/usr/bin/python
"""Usage: ./initial_db_population.py

The purpose of this script is to populate a database with
information about the devices connected to specific switches."""

import MySQLdb

# Open file with database credentials
file_name = '/path/to/database/credentials/file'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open file with SNMP credentials and database table name
# to store some of the found SNMP information
file_name = 'path/to/snmp/credentials/and/db/name/file'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]

# Open database connection
db = MySQLdb.connect(user=username,db=db_name,passwd=password)

# Prepare a cursor object
cursor = db.cursor()




# Retrieve SNMP information
#code


# Store SNMP information in database table
#code


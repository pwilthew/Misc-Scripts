#!/usr/bin/env python2
"""Script used to read and parse the web logs to get the 
names of the employees who open the link in the fake 
phishing email sent by `phishing.py`. Run as a cron job and
redirect stdout to `phished_employees.txt`."""

def main():

	my_file = open('/var/www/vhosts/system/example.com/logs/access_log', 'r')
	read_file = open('phished_employees.txt', 'r')
	read_list = read_file.readlines()

	for ln in my_file.readlines():
		if '.txt' and 'GET' in ln:
			phished = ((ln.split('GET /'))[1]).split('.txt')[0]
			phished += '\n'

			print phished  # This is stored in phished_employees.txt by the cron job


	my_file.close()
	read_file.close()


if __name__ == '__main__':
    main()



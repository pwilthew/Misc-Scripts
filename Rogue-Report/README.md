There are two subdirectories in here, *logs/* and *html/*. 

They should always have the same logs, but *html/* has them in html 
format and *logs/* in plaintext. 

The script is also in here, *create_rogue_report.py*. 

This script executes the command "show rogue ap summary ssid extended channel"
in the WAC. Its output gets saved in plaintext under a file in *logs/* and it is also
formatted to html and saved under *html/*.

The script is run daily as a cron job in /etc/cron.daily/create_rogue_report.sh 

create_rogue_report.sh only runs the following line to run the script:

`/usr/bin/python2 /root/rogue_report/create_rogue_report.py`


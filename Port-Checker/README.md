The purpose of this script is to determine if there are any unexpected running applications that have ports open for listening. Its goal is to detect if the machine has been compromised.

The `portchecker-with-netstat.py` is not reliable because someone with malicious intentions might have been replaced the netstat binary. Therefore, it is recommended to use `portchecker-without-netstat.py`.

## Use:

Edit the netports.csv file with the processes that are expected to be running in the machine you will execute the script and make sure both files are in the same directory.

The user executing the script should be root or a sudoer. 

`chmod +x portchecker-without-netstat.py`

`./portchecker-without-netstat.py`

or

`sudo ./portchecker-without-netstat.py`


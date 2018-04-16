PCI requirement 11. Implement processes to test
for the presence of wireless access points and detect and identify all
authorized and unathorized wireless access points on a quarterly basis.

The purpose of this script is to obtain the output of daily rogue scans
from the Wireless Access Controller (WAC) to verify that authorized and 
unauthorized wireless access points are identified.

This script executes the command "show rogue ap summary ssid extended channel"
in the WAC. Its output gets saved in plaintext under a file in *logs/* and it is also
formatted to html and saved under *html/*.




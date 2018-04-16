#!/usr/bin/env python2

import HTML
import sys

sys.dont_write_bytecode = True

def htmlify(log_path, html_path):
    log = open(log_path, 'r').readlines()[4:]
    html = open(html_path, 'w')

    list_of_lists = [
                     ['MAC Address', 
                      'Class', 
                      'State', 
                      'SSID', 
                      'Security', 
                      'Det-RadioType', 
                      'Channel', 
                      'RSSI(last/Max)', 
                      'On-wire',
                      'Ours']
                    ]

    for line in log:
        chars_in_line = list(line)
        if chars_in_line[0] == '-' or len(chars_in_line) <= 5:
            continue

        col = []

        # Append first 3 columns
        start_of_row = "".join(chars_in_line[0:52]).split()
        if start_of_row:
            for i in range(0,3):
                try:
                    col.append(start_of_row[i])
                except:
                    continue
        else:
            for i in range(0,3):
                col.append("")

        # Append SSID column
        col.append("".join(chars_in_line[52:72])) 

        # Append rest of the columns
        rest_of_row = "".join(chars_in_line[72:]).split()
        if rest_of_row:
            for i in range(0,5):
                try:
                    col.append(rest_of_row[i])
                except:
                    continue
        else:
            for i in range(0,5):
                col.append("")

        col.append("No")

        # Append list of columns
        list_of_lists.append(col)


    htmlcode = HTML.table(list_of_lists)
    html.write(htmlcode)



if __name__ == "__main__":
    htmlify(sys.argv[1], sys.argv[1]+'.html')

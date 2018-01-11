#!/usr/bin/env python2
"""Script used to send a fake phising email to employees
of the company in order to track who needs more Security
Awareness Training! :) 

The script `get-phished-employees.py` opens and parses the
web logs to get the names of the employees who open the
link in the fake phishing email."""

import smtplib

from email.mime.multipart import MIMEMultipart

from email.mime.text import MIMEText



def send_email(to_name, to_email):
    """Sends an email containing a link to "claim an Amazon
    Giftcard" to a given email address. This link is
    customized for each employee in order to be able to get
    the names of the employees who clicked it."""
    # Initialize SMTP server
    server = smtplib.SMTP('localhost',25)
    server.starttls()
    email_file = open('email.txt', 'r')
    from_ = '"Example Human Resources" <example-hr@example.com>'

    container = MIMEMultipart('alternative')
    container['Subject'] = 'Anniversary: Amazon Gift Card'
    container['From'] = from_
    container['To'] = to_email

    text = ''
    html = email_file.read()

    # The following line customizes the URL with the name
    # of the employee recipient of the email. 
    html = html.replace('REPLACEME', to_name + '.txt')
    email_file.close()

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    container.attach(part1)
    container.attach(part2)

    server.sendmail(from_, to_email, container.as_string())
    server.quit()

    return


def main():
    """Craft and send a fake phishing email to the randomly
    obtained email addresses of 10 employees."""
    employees_email_dic = {}

    my_file = open('10-Random-Employees.csv', 'r')

    for ln in my_file:
        empl, email = ln.split(', ')
        employees_email_dic[empl.strip(' ')] = email.strip('\n')

    for empl in employees_email_dic.keys():
        send_email(empl, employees_email_dic[empl])


if __name__ == '__main__':
    main()



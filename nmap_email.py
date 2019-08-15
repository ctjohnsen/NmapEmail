"""
NmapEmail.
**Author:** Christoffer Thorske Johnsen
**Created:** 15.08.2019
"""

import sys
import ssl
import smtplib
import subprocess
from xml.dom import minidom
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


def main():
    """Start of the program."""
    # Types of errors to handel in the sys.argv if arg is missing.
    errors = (ValueError, IndexError)
    ip_a = ''
    try:
        arg = sys.argv[1]
        ip_a = sys.argv[2]
    except errors:
        print('Use -new and ip address to make a new template or -ip and ip \
address to do nmap scan\n')
        exit()
    nmap(arg, ip_a)


def nmap(arg, ip_a):
    """Run the nmap scan."""
    # Set the date and commands to copy nmap.xml and make new nmap.xml
    now = datetime.now()
    old_xml_time = now.strftime("%d.%m.%Y")
    xml_file_name = ip_a + '_nmap.xml'
    old_xml = 'cp', xml_file_name, xml_file_name + '_' + old_xml_time
    nmap_scan = 'nmap', ip_a, '-p', '-', '-oX', xml_file_name
    new_nmap_scan = 'nmap', ip_a, '-p', '-', '-oX', 'new_' + xml_file_name
    if arg == '-new':
        subprocess.call(old_xml)
        subprocess.call(nmap_scan)
    elif arg == '-ip':
        subprocess.call(new_nmap_scan)
        new_ports(xml_file_name, ip_a)
    else:
        print('Use --new to make new template \
or just "python3 nmap_email.py" to run the program.')


def new_ports(xml_file_name, ip_a):
    """
    Find new open ports.
    Findes open ports from nmap.xml file and compare it with the new nmap
    scan file new_nmap.xml, and then print out the new ports that are opend
    """
    portnum = []
    new_portnum = []
    # exfiltrate open port from xml
    mydoc = minidom.parse(xml_file_name)
    items = mydoc.getElementsByTagName('port')
    for elem in items:
        portnum.append(elem.attributes['portid'].value)

    new_mydoc = minidom.parse('new_' + xml_file_name)
    new_items = new_mydoc.getElementsByTagName('port')
    for new_elem in new_items:
        new_portnum.append(new_elem.attributes['portid'].value)

    if portnum == new_portnum:
        print('\nNo new open ports')
    else:
        # Remove ports in the port_num from list new_portnum
        del_port = []
        new_open_port = []
        for a_port in portnum:
            try:
                new_portnum.remove(a_port)
            except (ValueError, IndexError):
                del_port.append(a_port)

        for b_port in new_portnum:
            new_open_port.append(b_port)

        print('\nRemoved port:')
        print(', '.join(del_port))

        print('\nNew ports:')
        print(', '.join(new_open_port))

        mail(new_open_port, del_port, ip_a)


def mail(new_open_port, del_port, ip_a):
    """Send mail with the new open ports."""
    sender_email = "SENDER"
    receiver_email = "RECEIVER"
    password = "PASSWORD"

    message = MIMEMultipart("alternative")
    message["Subject"] = "NmapEmail report"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    text = """\
    Report from NmapEmail scan

    New port open: %s
    Removed ports: %s
    on IP %s""" % (', '.join(new_open_port), ', '.join(del_port), ip_a)

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(MIMEText(text, "plain"))

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )
# if __name__ == '__mail__':


main()

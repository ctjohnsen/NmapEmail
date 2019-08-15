# NmapEmail

## Scan with nmap and send a mail if a new port is open.

### Install:
Nmap need to be installed. (*apt install nmap* on Ubuntu/Debian systems)
Sender_email, receiver_email and password needs to be added in **def mail**.

###To use
To use start with **python3 nmap_email.py -new *ip address to scan*** to make a template.
To compare template with a new scan run **python3 nmap_mail.py -ip *ip address to scan***

In **def nmap** you can change the syntax used with nmap.

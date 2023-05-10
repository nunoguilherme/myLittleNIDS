from scapy.all import *
import time
import smtplib

#Any contributions are welcome, any flaws you find, also please let me know in github! Thx

def packet_handler(pkt):
    if pkt.haslayer(TCP):
        handle_tcp(pkt)
    elif pkt.haslayer(UDP):
        handle_udp(pkt)
    elif pkt.haslayer(ICMP):
        handle_icmp(pkt)
    elif pkt.haslayer(DHCP):
        handle_dhcp(pkt)

# Variables to track TCP SYN and ACK packets
tcp_syn_counter = {}
tcp_ack_counter = {}

def handle_tcp(pkt):
    global tcp_syn_counter
    global tcp_ack_counter

    # Check for SYN flood attack
    if pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src
        tcp_syn_counter[src_ip] = tcp_syn_counter.get(src_ip, 0) + 1
    elif pkt[TCP].flags == 'A':
        src_ip = pkt[IP].src
        tcp_ack_counter[src_ip] = tcp_ack_counter.get(src_ip, 0) + 1

    # If the ratio of SYN to ACK packets is too high, it might be a SYN flood attack
    for ip in tcp_syn_counter:
        if tcp_syn_counter[ip] > 10 * tcp_ack_counter.get(ip, 1):
            alert('Possible SYN flood attack from {}'.format(ip))

# Variables to track UDP packets
udp_counter = {}

def handle_udp(pkt):
    global udp_counter

    src_ip = pkt[IP].src
    udp_counter[src_ip] = udp_counter.get(src_ip, 0) + 1

    # Check for UDP flood attack
    if udp_counter[src_ip] > 100:
        alert('Possible UDP flood attack from {}'.format(src_ip))

# Variables to track ICMP packets
icmp_counter = {}

def handle_icmp(pkt):
    global icmp_counter

    src_ip = pkt[IP].src
    icmp_counter[src_ip] = icmp_counter.get(src_ip, 0) + 1

    # Check for Ping flood attack
    if icmp_counter[src_ip] > 100:
        alert('Possible Ping flood attack from {}'.format(src_ip))

# Variables to track DHCP requests
dhcp_request_counter = {}

def handle_dhcp(pkt):
    global dhcp_request_counter

    mac_address = pkt[Ether].src
    dhcp_request_counter[mac_address] = dhcp_request_counter.get(mac_address, 0) + 1

    # Check for DHCP exhaustion attack
    if dhcp_request_counter[mac_address] > 10:
        alert('Possible DHCP exhaustion attack from MAC address {}'.format(mac_address))

def alert(message):
    print(message)


    # Set up email parameters
    from_email = 'your_email@example.com'
    from_password = 'your_email_password'
    to_email = 'recipient@example.com'
    subject = 'IDS Alert'

    # Create the email message
    email_message = 'Subject: {}\n\n{}'.format(subject, message)

    # Send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, email_message)
        server.quit()
    except Exception as e:
        print('Error sending email: {}'.format(e))

if __name__ == '__main__':
    try:
        print('Starting IDS...')
        sniff(iface='eth0', prn=packet_handler)
    except KeyboardInterrupt:
        print('Stopping IDS...')


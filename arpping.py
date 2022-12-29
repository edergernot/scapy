#! /usr/bin/env python
# arpping : arppings a network and outputs table as a result


import sys
from rich.console import Console
from rich.table import Table
from mac_vendor_lookup import MacLookup  #for Macvendor Lookup 
from scapy.all import srp, Ether, ARP, conf, get_if_addr, get_if_list
import ipaddress

networks = []
console = Console()

if len(sys.argv) < 2:
    interfaces = []
    routes = str(conf.route)
    for line in routes.split('\n'):
        try: 
            int(line[0]) # test if first caracter is decimal
        except:
            continue
        if line.split()[2]!="0.0.0.0": # ignore routes
            continue
        if line.split()[0][:-1]=="127.0.0.": # ignore loopback
            continue
        if line.split()[0][:-1]=="224.0.0.": # ignore multicast
            continue
        if line.split()[0] == "255.255.255.255": # ignore broadcast
            continue
        if line.split()[1] == "255.255.255.255": # ignore Hostroutes
            continue
        mask =  line.split()[1]
        net =  line.split()[0]
        network = str(ipaddress.ip_network(f'{net}/{mask}')) # generates CIDR from Netmask and Mask
        networks.append(network)
        interfaces.append(line.split()[3])
    console.print ("\nYou didn't add any prefix for Arpping, I will do Arpping for:", style="cyan")
    for network in networks:
        print (f'{network}')

if len(sys.argv) >= 2:
    networks.append(sys.argv[1])
    try:
        ipaddress.ip_network(networks[0])
    except:
        console.print (f'!!  "{networks[0]}" is Invalid  !!\nTry something like "192.168.1.0/24"', style="bright_red")
        sys.exit()   
    
for network in networks:  
    console.print (f"\nTry to ARP {network}\n", style="green3")
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                 timeout=2)
    
    print (f"Finished : found {len(ans)} Adresses")

    table = Table(title=f"ARP Table from Network:{network}")

    table.add_column("IP Address", style="magenta")
    table.add_column("MAC Address", style="cyan", no_wrap=True)
    table.add_column("Vendor",style="cyan")

    for snd,rcv in ans:
        addr = str(rcv.sprintf(r"%Ether.src%"))
        mac = MacLookup()
        try :
            vendor = mac.lookup(addr)
        except :
            vendor = "Unknown"
        ip = str(rcv.sprintf(r"%ARP.psrc%"))
        table.add_row(rcv.sprintf(r"%ARP.psrc%"),rcv.sprintf(r"%Ether.src%"),vendor  )
    
    print ("\n")
    console.print(table)

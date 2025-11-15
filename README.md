I began this project with the intention of making a firewall. I've instead made a simple implementation of Wireshark... I will call this project: 

##WireGuppy

Let me explain - 

I wanted to use raw sockets on macOS, so I used /dev/bpf0 (Berkeley Packet Filter). This filter allows me to sniff all packet traffic on my 
current network and display all kinds of cool information. I got to unwrap each layer of the packet: eth, ip, transport, until i got to the payload 
(which I ran through my version of strings to find any useful info)

This was as far as I could take the project using /dev/bpf0 because it does not give me the opportunitiy to make decisions on whether to 
accept or drop packets. So I have decided to use iptables and NFQueue on a Linux VM to take this project further. 

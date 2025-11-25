## WireGuppy

This project began as an attempt to build a simple firewall. Since my host machine runs macOS, I initially chose to work with the **Berkeley Packet Filter** (`/dev/bpf0`), believing it would give me the low-level packet access I needed. Instead, I quickly discovered that BPF on macOS is excellent for **sniffing** packets—but not for **filtering** them.

What started as a firewall experiment evolved into a lightweight, Wireshark-style packet sniffer.

Using `/dev/bpf0`, I was able to capture raw packet data from my network interface and manually walk through each layer of every frame:  

**Ethernet → IP → Transport → Payload**.  

For the payload, I even wrote a simple “strings-like” extractor to reveal anything human-readable inside the packet contents.

However, I eventually hit a fundamental limitation:  
**macOS BPF does not allow user programs to accept, drop, or modify packets.**  
It provides visibility, but not control. 

Because firewall logic requires decision-making (accept, drop, rate-limit, redirect), I’m continuing this work on a Linux OS using iptables and NFQUEUE, which allows for userspace packet filtering.

The continuation of this project will live in my firewall repo: https://github.com/gavincwyant/firewall

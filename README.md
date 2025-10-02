# Packet_sniffer
Packet Sniffer

# Compile:
```bash
qmake PacketSniffer.pro CONFIG+=release && make -j"$(nproc)"
```

# Clean project:
```bash
make distclean
```

# Ethernet II vs Linux Cooked Capture
At the moment when packet capturing starts, PacketWorker::process queries libpcap for the data link layer type (pcap_datalink) and passes the result to Sniffing::setLinkLayer. This means that whatever libpcap reports for the active interface directly controls the parsing logic in the application.

If the interface is the Linux pseudo-device any, libpcap returns DLT_LINUX_SLL, so our parser selects the branch with the “Linux Cooked Capture” header and displays the fields from the SLL header that describe the actual frame type and EtherType.

When we capture on a specific interface (e.g., wlan0 in managed mode), the kernel already provides “cooked” Ethernet II frames, and pcap_datalink returns DLT_EN10MB, so the UI shows a classic Ethernet II header.

Therefore, the difference in labels comes directly from the data link layer type reported by libpcap for the given interface.

# Something about Linux Cooked Capture 
Linux cooked capture, or SLL (sockaddr_ll), is a pseudo-protocol used by packet capture libraries like libpcap (for tcpdump and Wireshark) to capture packets from the "any" interface or devices without native link-layer headers. When capturing in this mode, libpcap uses a SOCK_DGRAM socket instead of a raw socket, and the kernel's socket code doesn't provide the original link-layer header. Instead, libpcap constructs a synthetic, 16-byte SLL header containing packet type and link-layer address information. 
## How it works:
### The Problem: 
A Linux system might have network interfaces with different link-layer types (e.g., Ethernet, Wi-Fi). Capturing on "any" interface would require a way to handle these different types. 
### The Solution: 
Instead of providing the real link-layer header, libpcap uses a SOCK_DGRAM socket. 
### SLL Header: 
The recvfrom() call on this socket supplies information, which libpcap uses to create a custom SLL header that includes:
Link-layer address: The source address of the packet. 
Packet type: Information about the protocol (e.g., Ethernet, IP). 
Benefits: This allows packet capture tools to capture traffic from various interface types and the any interface without needing to know all native link-layer formats beforehand. 

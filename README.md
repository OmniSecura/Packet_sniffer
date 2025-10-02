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
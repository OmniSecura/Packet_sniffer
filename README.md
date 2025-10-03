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

## Application Protocol Support
- HTTP request/response lines and headers are decoded and exposed in the packet details tree.
- DNS queries and responses include transaction metadata along with parsed questions, answers, authority and additional records.
- TLS handshakes surface record type, negotiated versions, SNI host names and cipher information for ClientHello/ServerHello messages.

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

# Follow Stream – Packet Capture, Stream Reconstruction & UI

## 1. Stream Collection and Reconstruction

The **packet capture loop** in `PacketWorker::process()` forwards each packet to `Sniffing::packet_callback()`, so this callback receives every frame seen during the sniffing session.

The `recordStreamSegment()` function parses Ethernet/IP/TCP–UDP headers to determine the **IP version**, ports, protocol, and a pointer to the payload. All non-TCP and non-UDP packets are discarded.

Addresses and ports are **ordered deterministically**:  
- The “A” and “B” endpoints are chosen by lexicographic order (IP and port).  
- The segment direction (`fromAtoB`) depends on whether the packet came from the initiator.  
- The **conversation key** is a 5-tuple:  
(IP version, protocol, A.ip, A.port, B.ip, B.port)

From each packet, a `StreamSegment` object is created containing:  
- Timestamp (seconds + microseconds)  
- Frame and payload lengths  
- Direction (A→B or B→A)  
- For TCP: flags, sequence/ack numbers, and window size  
- Payload data (copied if present)

Byte counters and aggregated payload buffers (`aggregatedAToB` / `aggregatedBToA`) are updated accordingly.

Each `StreamConversation` maintains:  
- Packet count  
- First and last timestamps  
- Conversation initiator  
- A vector of all segments belonging to that conversation

All conversations are stored in a **global `QHash`** protected by a mutex.  
- `getStreamConversations()` returns a list sorted by first-packet time and label.  
- `resetStreams()` clears the entire stream state.

---

## 2. User Interface (Follow Stream Dialog)

`MainWindow::openFollowStreamDialog()` creates a `FollowStreamDialog`, loads the current conversation list from the parser, and opens it as a **modal window**.

### Left Panel
- **Text filter**  
- **Conversation list** with label + metrics  
- **Initiator description** and conversation statistics  
- **Refresh** and **Reset** buttons  

### Right Panel
- **Direction selector:** both directions, A→B, B→A  
- **Format selector:** ASCII, hex dump, ASCII+hex table, C string, Base64  
- Metadata toggle (timestamps, sequence numbers, flags, etc.)  
- Line wrapping toggle  
- Integrated **search bar** (text field + Find Next/Previous)  
- **Payload view** area  
- Copy to clipboard & Save to file actions

---

## 3. Core UI Logic

- `setStreams()` stores the supplied conversation list.  
- `populateStreamList()` renders the list with text filtering (any substring).  
- When the selection changes, `updateDirectionCombo()` updates the direction options and shows the conversation initiator.  
- `shouldIncludeSegment()` respects the “Include empty packets” toggle.

### Rendering Segments
`buildSegmentBlock()` constructs text blocks for each segment:
- If metadata is enabled, a header line is added with:
- Timestamp (relative or absolute ISO 8601)
- Direction
- Payload length
- For TCP: seq/ack numbers, window size, and flags
- The payload is then rendered in the selected format.

`updatePayload()`:
- Applies line wrapping
- Filters segments by direction and payload presence
- Assembles text block by block
- Enables/disables Copy and Save buttons
- Updates statistics (packet counts per direction, byte totals, duration)

Search, clipboard, and save operations use Qt classes. `updateSearchControls()` enables search controls only when a pattern is entered.

---

## 4. Stream Management

- `reloadStreams()` refreshes the conversation list from the current sniffer state.  
- `clearStreams()` resets the global stream map and displays an empty view.

---

### Summary

The **Follow Stream** feature provides a full pipeline:
1. Capture → parse → classify → store TCP/UDP segments  
2. Aggregate and organize streams in real time  
3. Offer a powerful UI for filtering, inspecting, searching, and exporting payloads

This allows users to **easily reconstruct and analyze full conversations** from captured network traffic.

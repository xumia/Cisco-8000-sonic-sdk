# Packet Parser

## Overview

Identifying the packet format is required for packet processing. Parsing the packet to identify the packet format is performed in the Format Identifier Engine or *FIE*. The outcome of the parsed packet is the header stack which includes per header the type of header, its offset from the start of packet, and some additional metadata such as header errors or features identified during parsing. The parser engine is programable yet utilizes protocol specific hardwired logic to generate metadata, such as verifying IPv4 header integrity comparing calculated header checksum with the checksum stored on header.

Since at parse time, the headers required for processing the packet is unknown, the packet parser attempts to parse as many headers as possible. The data-path application is designed to maximize the parsing capabilities while attempting to preserve full performance for common network flows. However, there are some packet formats for which performance degradation is expected. The general restrictions are documented in the following section, and per header limitations are documented in the specific header documentation. 

Network facing interfaces expect the first header to be Ethernet type II header.

### Pacific FIE Hardware Restrictions

- Parsing is performed on the first 128B of the packet
- Parser can process up to 10 headers per packet  
- A single header's length cannot exceed 64B, unless it is the last processed header   
- Parsing is limited to 16 macro iterations per packet.
- Up to 8 macro iterations per packet (on average) can be processed at full performance. 
- There's no error indication incase parser did not complete to parse a specific header.

### Parsed Header Formats

- Ethernet Type II Frame
- IEEE 802.1q Vlan including 802.1ad
- ARP
- L2CP
- PTP
- MACSEC
- PFC
- LACP
- IPv4
- IPv6
- UDP
- TCP
- ICMP
- GRE
- MPLS
- VxLAN
- SYSTEM_INJECT
- SYSTEM_PUNT
- FABRIC
- TM

## Identified Packet Headers

### Ethernet

Ethernet Type II header is parsed and may optionally be followed by a single vlan tag with tpid of 0x8100 as specified in IEEE 802.1q or two vlan tags (QinQ) with tpid of 0x9100 or 0x88A8 followed by tpid 0x8100 as specified by IEEE 802.1ad. The ethertype field identifies the overlay protocol to be parsed. The following list of overlay protocols are identified.

#### Next protocols  

- IPv4
- IPv6  
- MPLS
- ARP
- PTP
- PFC
- LACP
- MACSEC
- L2CP
- SYSTEM_INJECT
- SYSTEM_PUNT  

#### Error Checks

- Source MAC address equals destination MAC address
- Source MAC address is has a multicast prefix

Additional checks are performed during packet processing.

#### Limitations

#### Performance

When the overlay protocol is one of IPv4, IPv6, or MPLS the performance is:

| Structure | Number of iterations | Number of headers | 
| --------- | -------------------- | ----------------- |
| Ethernet Type II |          1    |        1          |
| IEEE 802.1q vlan tag        | 2  |        2          | 
| IEEE 801.1ad QinQ vlan tags | 3  |        3          |

Otherwise, when the overlay protocol is not one of IPv4, IPv6, or MPLS the performance is:

| Structure | Number of iterations | Number of headers | 
| --------- | -------------------- | ----------------- |
| Ethernet Type II |          2    |        1          |
| IEEE 802.1q vlan tag        | 3  |        2          | 
| IEEE 801.1ad QinQ vlan tags | 4  |        3          |

### IPv4

IPv4 packet parsing performs basic header consistency checks and supports various overlay protocols including IPinIP, GRE, UDP, TCP, and ICMP.

#### Next protocols  

- IPV4
- IPV6  
- GRE
- UDP
- TCP

#### Error Checks

- IPv4 header checksum mismatch
- Version field is not 4
- Header length field is less than 5 (20B)
- Source IP address is a localhost address 127.0.0.0/8
- Source IP is multicast address 224.0.0.0/8
- Source IP is broadcast address 255.255.255.255/24

Additional checks are performed during packet processing.

#### Limitations

- Checksum is not checked in case IPv4 options are present
- The maximal supported size in bytes of the IPv4 options is 40B in addition to the 20B IPv4 header  

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| IPV4      |        1         |          1        |

### IPv6

IPv6 packet parsing performs basic header consistency checks and supports various overlay protocols including IPinIP, GRE, UDP, TCP, and ICMP. In addition up to 2 additional IPv6 Extension Headers are supported.
The following IPv6 Extension Headers are processed:
- Hop-By-Hop
- Destination
- Fragmentation
- Routing
- Authentication
- Mobility
- HIP
- SHIM6

#### Next protocols  

- IPv4
- IPv6
- UDP
- TCP
- GRE
- ICMP

#### Error Checks

- Version field is not 6
- Source IP address is 0::

Additional checks are performed during packet processing.

#### Limitations

- Up to two 8B IPv6 extension headers or a single 16B IPv6 extension header.

#### Performance

| Structure | Number of macros | Number of Headers |
| --------- | ---------------- | ----------------- |
| IPV6 no EH | 2               |         1         |
| IPV6 w 1 EH | 3              |         1         |
| IPV6 w 2 EH | 4              |         1         |
| IPV6 w Fragmentation Header | 4 |      1         |
| IPV6 w Fragmentation Header and 1 EH | 5 | 1     |

* In case a Hop-By-Hop Extension Header is processed parsing stops. Packet Processor will always punt the packet unless filtered in ACL.
  
### MPLS

MPLS header are parsed until the BOS flag is set on a label. It then speculatively identifies the overlay protocol by the first nibble (IP version field) passed the BOS label. The packet parser has no notion of the presence of control word and as such the next protocol may not be accurate.

#### Next protocols  

- IPv4
- IPv6
- Ethernet  

#### Error Checks

- IPv6 Null label present while next protocol is IPv4

#### Limitations

#### Performance

| Structure | Number of macros | Number of Headers |
| --------- | ---------------- | ----------------- |
| First MPLS label is not reserved | 2 + (Num labels / 5) | 1 |
| Reserved labels only  | 1+ Number of reserved labels | 2 |
| Reserved labels followed by more labels | 1 + Number of reserved labels + (Num labels / 5) | 2 |

### UDP

UDP headers are parsed and the overlay VxLAN is identified if present

#### Next protocols  

- VxLAN

#### Error Checks

#### Limitations

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| UDP | 1 | 1 |

### TCP

TCP header is not parsed. If present, it is the last protocol layer.

#### Next protocols  

No next protocols. Packet processing does not look passed the TCP header. It is always the last protocol.

#### Error Checks

#### Limitations

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| TCP | 1 | 1 |

### ICMP

ICMP header is not parsed. If present, it is the last protocol layer.

#### Next protocols  

#### Error Checks

#### Limitations

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| ICMP | 1 | 1 |

### GRE

#### Next protocols  

- IPv4
- IPv6
- Ethernet
- MPLS

#### Error Checks

#### Limitations

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| GRE | 1 | 1 |

### VXLAN

VxLAN header is parsed and the overlay protocol is expected to be Ethernet

#### Next protocols  

- Ethernet

#### Error Checks

#### Limitations

#### Performance

| Structure | Number of macros | Number of headers |
| --------- | ---------------- | ----------------- |
| VxLan | 1 | 1 |

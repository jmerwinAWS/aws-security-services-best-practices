
8.5. UDP keywords
8.5.1. udp.hdr

Sticky buffer to match on the whole UDP header.

Example rule:

alert udp any any -> any any (udp.hdr; content:"|00 08|"; offset:4; depth:2; sid:1234; rev:5;)

This example matches on the length field of the UDP header. In this case the length of 8 means that there is no payload. This can also be matched using dsize:0;.
8.6. ICMP keywords

ICMP (Internet Control Message Protocol) is a part of IP. IP at itself is not reliable when it comes to delivering data (datagram). ICMP gives feedback in case problems occur. It does not prevent problems from happening, but helps in understanding what went wrong and where. If reliability is necessary, protocols that use IP have to take care of reliability themselves. In different situations ICMP messages will be send. For instance when the destination is unreachable, if there is not enough buffer-capacity to forward the data, or when a datagram is send fragmented when it should not be, etcetera. More can be found in the list with message-types.

There are four important contents of a ICMP message on which can be matched with corresponding ICMP-keywords. These are: the type, the code, the id and the sequence of a message.
8.6.1. itype

The itype keyword is for matching on a specific ICMP type (number). ICMP has several kinds of messages and uses codes to clarify those messages. The different messages are distinct by different names, but more important by numeric values. For more information see the table with message-types and codes.

itype uses an unsigned 8-bit integer.

The format of the itype keyword:

itype:min<>max;
itype:[<|>]<number>;

Example This example looks for an ICMP type greater than 10:

itype:>10;

Example of the itype keyword in a signature:

alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4;)

The following lists all ICMP types known at the time of writing. A recent table can be found at the website of IANA

ICMP Type
	

Name

0
	

Echo Reply

3
	

Destination Unreachable

4
	

Source Quench

5
	

Redirect

6
	

Alternate Host Address

8
	

Echo

9
	

Router Advertisement

10
	

Router Solicitation

11
	

Time Exceeded

12
	

Parameter Problem

13
	

Timestamp

14
	

Timestamp Reply

15
	

Information Request

16
	

Information Reply

17
	

Address Mask Request

18
	

Address Mask Reply

30
	

Traceroute

31
	

Datagram Conversion Error

32
	

Mobile Host Redirect

33
	

IPv6 Where-Are-You

34
	

IPv6 I-Am-Here

35
	

Mobile Registration Request

36
	

Mobile Registration Reply

37
	

Domain Name Request

38
	

Domain Name Reply

39
	

SKIP

40
	

Photuris

41
	

Experimental mobility protocols such as Seamoby
8.6.2. icode

With the icode keyword you can match on a specific ICMP code. The code of a ICMP message clarifies the message. Together with the ICMP-type it indicates with what kind of problem you are dealing with. A code has a different purpose with every ICMP-type.

icode uses an unsigned 8-bit integer.

The format of the icode keyword:

icode:min<>max;
icode:[<|>]<number>;

Example: This example looks for an ICMP code greater than 5:

icode:>5;

Example of the icode keyword in a rule:

alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL MISC Time-To-Live Exceeded in Transit"; icode:0; itype:11; classtype:misc-activity; sid:2100449; rev:7;)

The following lists the meaning of all ICMP types. When a code is not listed, only type 0 is defined and has the meaning of the ICMP code, in the table above. A recent table can be found at the website of IANA

ICMP Code
	

ICMP Type
	

Description

3
	

0
	

Net Unreachable

1
	

Host Unreachable

2
	

Protocol Unreachable

3
	

Port Unreachable

4
	

Fragmentation Needed and Don't Fragment was Set

5
	

Source Route Failed

6
	

Destination Network Unknown

7
	

Destination Host Unknown

8
	

Source Host Isolated

9
	

Communication with Destination Network is Administratively Prohibited

10
	

Communication with Destination Host is Administratively Prohibited

11
	

Destination Network Unreachable for Type of Service

12
	

Destination Host Unreachable for Type of Service

13
	

Communication Administratively Prohibited

14
	

Host Precedence Violation

15
	

Precedence cutoff in effect

5
	

0
	

Redirect Datagram for the Network (or subnet)

1
	

Redirect Datagram for the Host

2
	

Redirect Datagram for the Type of Service and Network

3
	

Redirect Datagram for the Type of Service and Host

9
	

0
	

Normal router advertisement

16
	

Doesn't route common traffic

11
	

0
	

Time to Live exceeded in Transit

1
	

Fragment Reassembly Time Exceeded

12
	

0
	

Pointer indicates the error

1
	

Missing a Required Option

2
	

Bad Length

40
	

0
	

Bad SPI

1
	

Authentication Failed

2
	

Decompression Failed

3
	

Decryption Failed

4
	

Need Authentication

5
	

Need Authorization
8.6.3. icmp_id

With the icmp_id keyword you can match on specific ICMP id-values. Every ICMP-packet gets an id when it is being send. At the moment the receiver has received the packet, it will send a reply using the same id so the sender will recognize it and connects it with the correct ICMP-request.

Format of the icmp_id keyword:

icmp_id:<number>;

Example: This example looks for an ICMP ID of 0:

icmp_id:0;

Example of the icmp_id keyword in a rule:

alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4;)
8.6.4. icmp_seq

You can use the icmp_seq keyword to check for a ICMP sequence number. ICMP messages all have sequence numbers. This can be useful (together with the id) for checking which reply message belongs to which request message.

Format of the icmp_seq keyword:

icmp_seq:<number>;

Example: This example looks for an ICMP Sequence of 0:

icmp_seq:0;

Example of icmp_seq in a rule:

alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4;)

Note

Some pcap analysis tools, like wireshark, may give both a little endian and big endian value for icmp_seq. The icmp_seq keyword matches on the big endian value, this is due to Suricata using the network byte order (big endian) to perform the match comparison.
8.6.5. icmpv4.hdr

Sticky buffer to match on the whole ICMPv4 header.
8.6.6. icmpv6.hdr

Sticky buffer to match on the whole ICMPv6 header.
8.6.7. icmpv6.mtu

Match on the ICMPv6 MTU optional value. Will not match if the MTU is not present.

icmpv6.mtu uses an unsigned 32-bit integer.

The format of the keyword:

icmpv6.mtu:<min>-<max>;
icmpv6.mtu:[<|>]<number>;
icmpv6.mtu:<value>;

Example rule:

alert ip $EXTERNAL_NET any -> $HOME_NET any (icmpv6.mtu:<1280; sid:1234; rev:5;)

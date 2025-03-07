
8.15. DNS Keywords

Suricata supports sticky buffers as well as keywords for efficiently matching on specific fields in DNS messages.

Note that sticky buffers are expected to be followed by one or more Payload Keywords.
8.15.1. dns.opcode

This keyword matches on the opcode found in the DNS header flags.

dns.opcode uses an unsigned 8-bit integer.
8.15.1.1. Syntax

dns.opcode:[!]<number>
dns.opcode:[!]<number1>-<number2>

8.15.1.2. Examples

Match on DNS requests and responses with opcode 4:

dns.opcode:4;

Match on DNS requests where the opcode is NOT 0:

dns.opcode:!0;

Match on DNS requests where the opcode is between 7 and 15, exclusively:

    dns.opcode:7-15;

Match on DNS requests where the opcode is not between 7 and 15:

    dns.opcode:!7-15;

8.15.2. dns.rcode

This keyword matches on the rcode field found in the DNS header flags.

dns.rcode uses an unsigned 8-bit integer.

Currently, Suricata only supports rcode values in the range [0-15], while the current DNS version supports rcode values from [0-23] as specified in RFC 6895.

We plan to extend the rcode values supported by Suricata according to RFC 6895 as tracked by the ticket: https://redmine.openinfosecfoundation.org/issues/6650
8.15.2.1. Syntax

dns.rcode:[!]<number>
dns.rcode:[!]<number1>-<number2>

8.15.2.2. Examples

Match on DNS requests and responses with rcode 4:

dns.rcode:4;

Match on DNS requests and responses where the rcode is NOT 0:

dns.rcode:!0;

8.15.3. dns.rrtype

This keyword matches on the rrtype (integer) found in the DNS message.

dns.rrtype uses an unsigned 16-bit integer.
8.15.3.1. Syntax

dns.rrtype:[!]<number>

8.15.3.2. Examples

Match on DNS requests and responses with rrtype 4:

dns.rrtype:4;

Match on DNS requests and responses where the rrtype is NOT 0:

dns.rrtype:!0;

8.15.4. dns.query

dns.query is a sticky buffer that is used to inspect DNS query names in DNS request messages. Example:

alert dns any any -> any any (msg:"Test dns.query option"; dns.query; content:"google"; nocase; sid:1;)

Being a sticky buffer, payload keywords such as content are to be used after dns.query:
../_images/dns_query.png

The dns.query keyword affects all following contents, until pkt_data is used or it reaches the end of the rule.

Note

dns.query is equivalent to the older dns_query.

Note

dns.query will only match on DNS request messages, to also match on DNS response message, see dns.queries.rrname.

dns.queries.rrname supports Multiple Buffer Matching.
8.15.4.1. Normalized Buffer

Buffer contains literal domain name

    <length> values (as seen in a raw DNS request) are literal '.' characters

    no leading <length> value

    No terminating NULL (0x00) byte (use a negated relative isdataat to match the end)

Example DNS request for "mail.google.com" (for readability, hex values are encoded between pipes):

DNS query on the wire (snippet):

|04|mail|06|google|03|com|00|

dns.query buffer:

mail.google.com

8.15.5. dns.queries.rrname

dns.queries.rrname is a sticky buffer that is used to look at the name field in DNS query (question) resource records. It is nearly identical to dns.query but supports both DNS requests and responses.

dns.queries.rrname will look at both requests and responses, so flow is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled resource name, for example "www.suricata.io".

dns.queries.rrname supports Multiple Buffer Matching.

dns.queries.rrname was introduced in Suricata 8.0.0.
8.15.6. dns.answers.rrname

dns.answers.rrname is a sticky buffer that is used to look at the name field in DNS answer resource records.

dns.answers.rrname will look at both requests and responses, so flow is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled resource name, for example "www.suricata.io".

dns.answers.rrname supports Multiple Buffer Matching.

dns.answers.rrname was introduced in Suricata 8.0.0.
8.15.7. dns.authorities.rrname

dns.authorities.rrname is a sticky buffer that is used to look at the rrname field in DNS authority resource records.

dns.authorities.rrname will look at both requests and responses, so flow is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled resource name, for example "www.suricata.io".

dns.authorities.rrname supports Multiple Buffer Matching.

dns.authorities.rrname was introduced in Suricata 8.0.0.
8.15.8. dns.additionals.rrname

dns.additionals.rrname is a sticky buffer that is used to look at the rrname field in DNS additional resource records.

dns.additionals.rrname will look at both requests and responses, so flow is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled resource name, for example "www.suricata.io".

dns.additionals.rrname supports Multiple Buffer Matching.

dns.additionals.rrname was introduced in Suricata 8.0.0.
8.15.9. dns.response.rrname

dns.response.rrname is a sticky buffer that is used to look at all name and rdata fields of DNS response (answer) resource records that are represented as a resource name (hostname). It supports inspecting all DNS response sections. Example:

alert dns any any -> any any (msg:"Test dns.response.rrname option"; \
    dns.response.rrname; content:"google"; nocase; sid:1;)

rdata field matching supports a subset of types that contain domain name structured data, for example: "www.suricata.io". The list of types inspected is:

    CNAME

    PTR

    MX

    NS

    SOA (mname data: primary name server)

The buffer being matched on contains the complete re-assembled resource name, for example "www.suricata.io".

dns.response.rrname supports Multiple Buffer Matching.

dns.response.rrname was introduced in Suricata 8.0.0.


8.53. Rule Types and Categorization

Once parsed, Suricata rules are categorized for performance and further processing (as different rule types will be handled by specific engine modules). The signature types are defined in src/detect.h:
src/detect.h

enum SignatureType {
    SIG_TYPE_NOT_SET = 0,
    SIG_TYPE_IPONLY,      // rule is handled by IPONLY engine
    SIG_TYPE_LIKE_IPONLY, // rule is handled by pkt engine, has action effect like ip-only
    /** Proto detect only signature.
     *  Inspected once per direction when protocol detection is done. */
    SIG_TYPE_PDONLY, // rule is handled by PDONLY engine
    SIG_TYPE_DEONLY,
    SIG_TYPE_PKT,
    SIG_TYPE_PKT_STREAM,
    SIG_TYPE_STREAM,

    SIG_TYPE_APPLAYER, // app-layer but not tx, e.g. appproto
    SIG_TYPE_APP_TX,   // rule is handled by TX engine

    SIG_TYPE_MAX,
};

In more human readable terms:
Suricata Rule Types, and their Engine Analysis Term

Rule Type
	

Code Symbol
	

Engine-Analysis Representation

Decoder Events Only
	

SIG_TYPE_DEONLY
	

de_only

Packet
	

SIG_TYPE_PKT
	

pkt

IP Only
	

SIG_TYPE_IPONLY
	

ip_only

IP Only (contains negated address(es))
	

SIG_TYPE_LIKE_IPONLY
	

like_ip_only

Protocol Detection Only
	

SIG_TYPE_PDONLY
	

pd_only

Packet-Stream
	

SIG_TYPE_PKT_STREAM
	

pkt_stream

Stream
	

SIG_TYPE_STREAM
	

stream

Application Layer Protocol
	

SIG_TYPE_APPLAYER
	

app_layer

Application Layer Protocol Transactions
	

SIG_TYPE_APP_TX
	

app_tx

The rule type will impact:

        To what does the signature action apply, in case of a match (Action Scope)

        When is the rule matched against traffic (Inspection Hook)

        Against what the rule matches (Data Exposed)

This categorization is done taking into consideration the presence or absence of certain rule elements, as well as the type of keywords used. The categorization currently takes place in src/detect-engine-build.c:void SignatureSetType().

The SignatureSetType() overall flow is described below:
A flowchart representing the SignatureSetType function.

Flowcharts expanding uncovered functions or portions of the overall algorithm above are shown in the Detailed Flowcharts section.

The following table lists all Suricata signature types, and how they impact the aspects aforementioned.
Suricata Rule Types

Type
	

Action Scope
	

Inspection Hook
	

Data Exposed
	

Keyword Examples

(non-exhaustive)

Decoder Events Only

(de_only)
	

Packet
	

Per-broken/ invalid packet
	

Decoding events
	

decode-event

Packet

(pkt)
	

Packet
	

Per-packet basis
	

Packet-level info (e.g.: header info)
	

tcp-pkt, itype, tcp.hdr, tcp.seq, ttl etc.

IP Only

(ip_only)
	

Flow (if existing). Packets (if not part of a flow)
	

Once per direction
	

IP addresses on the flow
	

Source/ Destination field of a rule

IP Only (contains negated address) 2

(like_ip_only)
	

Flow
	

All packets
	

IP addresses on the flow
	

Source/ Destination field of a rule containing negated address

Protocol Detection Only

(pd_only)
	

Flow
	

Once per direction, when protocol detection is done
	

Protocol detected for the flow
	

app-layer-protocol

Packet-Stream

(pkt_stream)
	

Flow, if stateful 1
	

Per stream chunk, if stateful, per-packet if not

(stream payload AND packet payload)
	

The reassembled stream and/or payload data
	

content with startswith or depth

Stream

(stream)
	

Flow, if stateful 1
	

Stream chunks, if stateful, just packets if not
	

Stream reassembled payload or packet payload data
	

tcp-stream in protocol field; simple content; byte_extract

Application Layer Protocol

(app_layer)
	

Flow
	

Per-packet basis
	

'protocol' field in a rule
	

Protocol field of a rule

Application Layer Protocol Transactions

(app_tx)
	

Flow
	

Per transaction update
	

Buffer keywords
	

Application layer protocol-related, e.g. http.host, rfb.secresult, dcerpc.stub_data, frame keywords

Note

Action Scope: Flow, if stateful

(1) Apply to the flow. If a segment isn't accepted into a stream for any reason (such as packet anomalies, errors, memcap reached etc), the rule will be applied on a packet level.

Warning

Although both are related to matching on application layer protocols, as the table suggests, since Suricata 7 a Protocol Detection rule (that uses the app-layer-protocol keyword) is not internally classified the same as a rule simply matching on the application layer protocol on the protocol field.
8.53.1. Signature Properties

The Action Scope mentioned above relates to the Signature Properties, as seen in src/detect-engine.c:
src/detect-engine.c

const struct SignatureProperties signature_properties[SIG_TYPE_MAX] = {
    /* SIG_TYPE_NOT_SET */      { SIG_PROP_FLOW_ACTION_PACKET, },
    /* SIG_TYPE_IPONLY */       { SIG_PROP_FLOW_ACTION_FLOW, },
    /* SIG_TYPE_LIKE_IPONLY */  { SIG_PROP_FLOW_ACTION_FLOW, },
    /* SIG_TYPE_PDONLY */       { SIG_PROP_FLOW_ACTION_FLOW, },
    /* SIG_TYPE_DEONLY */       { SIG_PROP_FLOW_ACTION_PACKET, },
    /* SIG_TYPE_PKT */          { SIG_PROP_FLOW_ACTION_PACKET, },
    /* SIG_TYPE_PKT_STREAM */   { SIG_PROP_FLOW_ACTION_FLOW_IF_STATEFUL, },
    /* SIG_TYPE_STREAM */       { SIG_PROP_FLOW_ACTION_FLOW_IF_STATEFUL, },
    /* SIG_TYPE_APPLAYER */     { SIG_PROP_FLOW_ACTION_FLOW, },
    /* SIG_TYPE_APP_TX */       { SIG_PROP_FLOW_ACTION_FLOW, },
};

8.53.1.1. Signature: Require Real Packet

Aside from the scope of action of a signature, certain rule conditions will require that it matches against a real packet (as opposed to a pseudo packet). These rules are flagged with SIG_MASK_REQUIRE_REAL_PKT by the engine, and will have real_pkt listed as one of the rule's requirements. (See engine-analysis example output for the Packet rule type.)

A pseudo packet is an internal resource used by the engine when a flow is over but there is still data to be processed, such as when there is a flow timeout. A fake packet is then injected in the flow to finish up processing before ending it.

Those two types will be more documented soon (tracking #7424).
8.53.2. Signature Types and Variable-like Keywords

Keywords such as flow variables (flowint, flowbits), datasets, and similar ones can alter the rule type, if present in a signature.

That happens because the variable condition can change per packet. Thus, the Signature is categorized as a packet rule.

This affects rule types:

        Application Layer (app_layer)

        Protocol Detection Only (pd_only)

        Decoder Events Only (de_only)

        IP Only (ip_only) 3

        Like IP Only (like_ip_only) 3

The rule examples provided further cover some such cases, but the table below lists those keywords with more details:
Variable-like Keywords

Keyword
	

Keyword Option
	

Rule Type change?

flow
	

to_server, to_client
	

no type changes 3

flow
	

established, not_established
	

to packet

flowbits, xbits, hostbits
	

isset, isnotset
	

to packet

flowbits, xbits, hostbits
	

set, unset, toggle
	

no type change

flowint
	

isset, notset, all operators
	

to packet

flowint
	

defining the variable; unseting;
	

no type change

iprep
	

isset, notset, all operators
	

to packet

Note

IP Only and Like IP Only

(3) Unlike the other affected types, signatures that would otherwise be classified as ip_only or like_ip_only become Packet rules if the flow keyword is used, regardless of option.

Note

dataset, while may look similar to the keywords above, doesn't pertain to this list as it can only be used with sticky buffer keywords, thus being only available to Application Layer Transaction rules (app_tx), which are not affected by this.
8.53.2.1. Flowbits: isset

If a non-stateful rule (e.g. a pkt rule) checks if a flowbit is set (like in flowbits:fb6,isset) and the rule that sets that variable is a stateful one, such as an app_tx rule, the engine will set a flag to indicate that that rule is also stateful - without altering its signature type. This flag is currently SIG_FLAG_INIT_STATE_MATCH (cf. ticket #7483).

There is a work-in-progress to add information about this to the engine-analysis report (ticket #7456).
8.53.3. Signatures per Type

This section offers brief descriptions for each rule type, and illustrates what signatures of each type may look like. It is possible to learn the type of a signature, as well as other important information, by running Suricata in engine analysis mode.

For each rule type, there is also a sample of the Engine Analysis report for one or more of rule(s) shown.
8.53.3.1. Decoder Events Only

Signatures the inspect broken or invalid packets. They expose Suricata decoding events.

For more examples check https://github.com/OISF/suricata/blob/master/rules/decoder-events.rules.
8.53.3.1.1. Example

alert pkthdr any any -> any any (msg:"SURICATA IPv6 duplicated Hop-By-Hop Options extension header"; decode-event:ipv6.exthdr_dupl_hh; classtype:protocol-command-decode; sid:1101;)

drop pkthdr any any -> any any (msg:"SURICATA IPv4 invalid option length"; :example-rule-emphasis:`decode-event:ipv4.opt_invalid_len; classtype:protocol-command-decode; sid:2200005; rev:2;)
8.53.3.1.2. Engine-Analysis Report

{
  "raw": "alert pkthdr any any -> any any (msg:\"SURICATA IPv6 duplicated Hop-By-Hop Options extension header\"; decode-event:ipv6.exthdr_dupl_hh; classtype:protocol-command-decode; sid:1101;)",
  "id": 1101,
  "gid": 1,
  "rev": 0,
  "msg": "SURICATA IPv6 duplicated Hop-By-Hop Options extension header",
  "app_proto": "unknown",
  "requirements": [
    "engine_event"
  ],
  "type": "de_only",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [
    {
      "name": "packet",
      "is_mpm": false
    }
  ],
  "frame_engines": [],
  "lists": {
    "packet": {
      "matches": [
        {
          "name": "decode-event"
        }
      ]
    }
  }
}

8.53.3.2. Packet

Rules that expose/ inspect information on a packet-level (for instance, the header). Certain flow keywords may also turn a rule into a pkt rule, if they require per-packet inspection (cf. Signature Types and Variable-like Keywords).
8.53.3.2.1. Examples

alert tcp-pkt any any -> any any (msg:"tcp-pkt, anchored content"; content:"abc"; startswith; sid:203;)

alert tcp any any -> any any (msg:"ttl"; ttl:123; sid:701;)

alert udp any any -> any any (msg:"UDP with flow direction"; flow:to_server; sid:1001;)

alert tcp any any -> any 443 (flow: to_server; flowbits:set,tls_error; sid:1604; msg:"Allow TLS error handling (outgoing packet) - non-stateful rule";)

alert tcp-pkt any any -> any any (msg:"Flowbit isset"; flowbits:isset,fb6; flowbits:isset,fb7; sid:1919;)
8.53.3.2.2. Engine-Analysis Report

{
  "raw": "alert tcp-pkt any any -> any any (msg:\"tcp-pkt, anchored content\"; content:\"abc\"; startswith; sid:203;)",
  "id": 203,
  "gid": 1,
  "rev": 0,
  "msg": "tcp-pkt, anchored content",
  "app_proto": "unknown",
  "requirements": [
    "payload",
    "real_pkt"
  ],
  "type": "pkt",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "need_packet",
    "toserver",
    "toclient",
    "prefilter"
  ],
  "pkt_engines": [
    {
      "name": "payload",
      "is_mpm": true
    }
  ],
  "frame_engines": [],
  "lists": {
    "payload": {
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": true,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "depth": 3,
            "fast_pattern": false,
            "relative_next": false
          }
        }
      ]
    }
  },
  "mpm": {
    "buffer": "payload",
    "pattern": "abc",
    "length": 3,
    "nocase": false,
    "negated": false,
    "starts_with": true,
    "ends_with": false,
    "is_mpm": true,
    "no_double_inspect": false,
    "depth": 3,
    "fast_pattern": false,
    "relative_next": false
  }
}

8.53.3.3. IP Only

The IP ONLY rule type is used when rules match only on source and destination IP addresses, and not on any other flow or content modifier.
8.53.3.3.1. Examples

alert tcp-stream any any -> any any (msg:"tcp-stream, no content"; sid:101;)

alert tcp-pkt [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12] any -> any any (msg:"tcp-pkt, no content"; sid:201;)

alert ip any any -> any any (hostbits:set,myflow2; sid:1505;)

alert udp any any -> any any (msg:"UDP with flow direction"; sid:1601;)
8.53.3.3.2. Engine-Analysis Report

{
  "raw": "alert ip any any -> any any (hostbits:set,myflow2; sid:1505;)",
  "id": 1505,
  "gid": 1,
  "rev": 0,
  "app_proto": "unknown",
  "requirements": [],
  "type": "ip_only",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [],
  "frame_engines": [],
  "lists": {
    "postmatch": {
      "matches": [
        {
          "name": "hostbits"
        }
      ]
    }
  }
}

8.53.3.4. IP Only (contains negated address)

A rule that inspects IP only properties, but contains negated IP addresses.

IP Only signatures with negated addresses are like IP-only signatures, but currently handled differently due to limitations of the algorithm processing IP Only rules. Impactful differences from a user-perspective are listed on the Signature Types table.
8.53.3.4.1. Examples

alert tcp 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 any -> ![192.168.0.0/16,10.0.0.0/8,172.16.0.0/12] any (msg:"tcp, has negated IP address"; sid:304;)

alert tcp [10.0.0.0/8,!10.10.10.10] any -> [10.0.0.0/8,!10.10.10.10] any (msg:"tcp, has negated IP address"; sid:305;)
8.53.3.4.2. Engine-Analysis Report

{
  "raw": "alert tcp [10.0.0.0/8,!10.10.10.10] any -> [10.0.0.0/8,!10.10.10.10] any (msg:\"tcp, has negated IP address\"; sid:305;)",
  "id": 305,
  "gid": 1,
  "rev": 0,
  "msg": "tcp, has negated IP address",
  "app_proto": "unknown",
  "requirements": [],
  "type": "like_ip_only",
  "flags": [
    "sp_any",
    "dp_any",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [],
  "frame_engines": [],
  "lists": {}
}

8.53.3.5. Protocol Detection Only

When a signature checks for the application layer protocol but there is no need for a per-packet inspection, protocol detection can be done with the app-layer-protocol keyword. Check the keyword documentation full for usage.

See Protocol Detection Only for a flowchart representing how the type is defined.

See Application Layer Protocol for a packet-based inspection.

Warning

Since Suricata 7, a Protocol Detection rule (that uses the app-layer-protocol keyword) is not internally classified the same as a rule simply matching on the application layer protocol on the protocol field.
8.53.3.5.1. Examples

alert tcp any any -> any any (msg:"tcp, pd negated"; app-layer-protocol:!http; sid:401;)

alert tcp any any -> any any (msg:"tcp, pd positive"; app-layer-protocol:http; sid:402;)

alert tcp any any -> any any (msg:"tcp, pd positive dns"; app-layer-protocol:dns; sid:403;)

alert tcp any any -> any any (msg:"tcp, pd positive, dns, flow:to_server"; app-layer-protocol:dns; flow:to_server; sid:405;)
8.53.3.5.2. Engine-Analysis Report

{
  "raw": "alert tcp any any -> any any (msg:\"tcp, pd positive dns\"; app-layer-protocol:dns; sid:403;)",
  "id": 403,
  "gid": 1,
  "rev": 0,
  "msg": "tcp, pd positive dns",
  "app_proto": "unknown",
  "requirements": [],
  "type": "pd_only",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [
    {
      "name": "packet",
      "is_mpm": false
    }
  ],
  "frame_engines": [],
  "lists": {
    "packet": {
      "matches": [
        {
          "name": "app-layer-protocol"
        }
      ]
    }
  }
}

8.53.3.6. Packet-Stream

A rule is categorized as such when it inspects on traffic in specific portions of the packet payload, using content buffer with the startswith or depth keywords.
8.53.3.6.1. Examples

alert tcp any any -> any any (msg:"tcp, anchored content"; content:"abc"; startswith; sid:303;)

alert http any any -> any any (msg:"http, anchored content"; content:"abc"; depth:30; sid:603;)
8.53.3.6.2. Engine-Analysis Report

{
  "raw": "alert http any any -> any any (msg:\"http, anchored content\"; content:\"abc\"; depth:30; sid:603;)",
  "id": 603,
  "gid": 1,
  "rev": 0,
  "msg": "http, anchored content",
  "app_proto": "http_any",
  "requirements": [
    "payload",
    "flow"
  ],
  "type": "pkt_stream",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "applayer",
    "need_packet",
    "need_stream",
    "toserver",
    "toclient",
    "prefilter"
  ],
  "pkt_engines": [
    {
      "name": "payload",
      "is_mpm": true
    }
  ],
  "frame_engines": [],
  "lists": {
    "payload": {
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "depth": 30,
            "fast_pattern": false,
            "relative_next": false
          }
        }
      ]
    }
  },
  "mpm": {
    "buffer": "payload",
    "pattern": "abc",
    "length": 3,
    "nocase": false,
    "negated": false,
    "starts_with": false,
    "ends_with": false,
    "is_mpm": true,
    "no_double_inspect": false,
    "depth": 30,
    "fast_pattern": false,
    "relative_next": false
  }
}

8.53.3.7. Stream

A rule that matches payload traffic without regards to its position, that is, on an unanchored content buffer, uses byte extraction or matches on tcp-stream is classified a stream rule.
8.53.3.7.1. Examples

alert tcp-stream any any -> any any (msg:"tcp-stream, simple content"; content:"abc"; sid:102;)

alert http any any -> any any (msg:"http, simple content"; content:"abc"; sid:602;)

alert tcp any any -> any 443 (flow: to_server; content:"abc"; flowbits:set,tls_error; sid:1605; msg:"Allow TLS error handling (outgoing packet) with simple content - Stream rule";)

alert tcp any any -> any 443 (flow: to_server; content:"abc"; sid:160401; msg:"Allow TLS error handling (outgoing packet) - stream rule";)

alert tcp any any -> any 443 (content:"abc"; sid:160402; msg:"Allow TLS error handling (outgoing packet) - stream rule";)

alert tcp any any -> any any (msg:"byte_extract with dce"; byte_extract:4,0,var,dce; byte_test:4,>,var,4,little; sid:901;)
8.53.3.7.2. Engine-Analysis Report

{
  "raw": "alert tcp any any -> any any (msg:\"byte_extract with dce\"; byte_extract:4,0,var,dce; byte_test:4,>,var,4,little; sid:901;)",
  "id": 901,
  "gid": 1,
  "rev": 0,
  "msg": "byte_extract with dce",
  "app_proto": "dcerpc",
  "requirements": [
    "payload",
    "flow"
  ],
  "type": "stream",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "applayer",
    "need_stream",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [
    {
      "name": "payload",
      "is_mpm": false
    }
  ],
  "frame_engines": [],
  "lists": {
    "payload": {
      "matches": [
        {
          "name": "byte_extract"
        },
        {
          "name": "byte_test",
          "byte_test": {
            "nbytes": 4,
            "offset": 4,
            "base": "unset",
            "flags": [
              "little_endian"
            ]
          }
        }
      ]
    }
  }
}

8.53.3.8. Application Layer Protocol

For a packet-based inspection of the application layer protocol, a rule should use the protocol field for the matches.

Warning

Since Suricata 7, a simple rule matching traffic on the protocol field is not internally classified the same as a rule using the app-layer-protocol keyword).

Warning

As per Suricata 7, if flow:established or flow:not_established is added to a base Application Layer Protocol rule, that signature will become a Packet rule.
8.53.3.8.1. Examples

alert dns any any -> any any (msg:"app-layer, dns"; sid:404;)

alert http any any -> any any (msg:"http, no content"; sid:601;)

alert tls any any -> any any (msg:"tls, pkt or app-layer?"; flowint:tls_error_int,=,0; sid:613;)
8.53.3.8.2. Engine-Analysis Report

{
  "raw": "alert dns any any -> any any (msg:\"app-layer, dns\"; sid:404;)",
  "id": 404,
  "gid": 1,
  "rev": 0,
  "msg": "app-layer, dns",
  "app_proto": "dns",
  "requirements": [
    "flow"
  ],
  "type": "app_layer",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "applayer",
    "toserver",
    "toclient"
  ],
  "pkt_engines": [],
  "frame_engines": [],
  "lists": {}
}

8.53.3.9. Application Layer Protocol Transactions

Rules inspecting traffic using keywords related to application layer protocols are classified with this signature type. This also includes frame keywords.
8.53.3.9.1. Examples

alert tcp any any -> any any (msg:"http, pos event"; app-layer-event:http.file_name_too_long; sid:501;)

alert http any any -> any any (msg:"Test"; flow:established,to_server; http.method; content:"GET"; http.uri; content:".exe"; endswith; http.host; content:!".google.com"; endswith; sid:1102;)

alert udp any any -> any any (msg:"DNS UDP Frame"; flow:to_server; frame:dns.pdu; content:"|01 20 00 01|"; offset:2; content:"suricata"; offset:13; sid:1402; rev:1;)

alert tcp any any -> any any (msg:"byte_extract with dce"; dcerpc.stub_data; content:"abc"; byte_extract:4,0,var,relative; byte_test:4,>,var,4,little; sid:902;)
8.53.3.9.2. Engine-Analysis Report

{
  "raw": "alert tcp any any -> any any (msg:\"byte_extract with dce\"; dcerpc.stub_data; content:\"abc\"; byte_extract:4,0,var,relative; byte_test:4,>,var,4,little; sid:902;)",
  "id": 902,
  "gid": 1,
  "rev": 0,
  "msg": "byte_extract with dce",
  "app_proto": "dcerpc",
  "requirements": [
    "flow"
  ],
  "type": "app_tx",
  "flags": [
    "src_any",
    "dst_any",
    "sp_any",
    "dp_any",
    "applayer",
    "toserver",
    "toclient",
    "prefilter"
  ],
  "pkt_engines": [],
  "frame_engines": [],
  "engines": [
    {
      "name": "dce_stub_data",
      "direction": "toclient",
      "is_mpm": true,
      "app_proto": "dcerpc",
      "progress": 0,
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "fast_pattern": false,
            "relative_next": true
          }
        },
        {
          "name": "byte_extract"
        },
        {
          "name": "byte_test",
          "byte_test": {
            "nbytes": 4,
            "offset": 4,
            "base": "unset",
            "flags": [
              "little_endian"
            ]
          }
        }
      ]
    },
    {
      "name": "dce_stub_data",
      "direction": "toserver",
      "is_mpm": true,
      "app_proto": "dcerpc",
      "progress": 0,
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "fast_pattern": false,
            "relative_next": true
          }
        },
        {
          "name": "byte_extract"
        },
        {
          "name": "byte_test",
          "byte_test": {
            "nbytes": 4,
            "offset": 4,
            "base": "unset",
            "flags": [
              "little_endian"
            ]
          }
        }
      ]
    },
    {
      "name": "dce_stub_data",
      "direction": "toclient",
      "is_mpm": true,
      "app_proto": "smb",
      "progress": 0,
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "fast_pattern": false,
            "relative_next": true
          }
        },
        {
          "name": "byte_extract"
        },
        {
          "name": "byte_test",
          "byte_test": {
            "nbytes": 4,
            "offset": 4,
            "base": "unset",
            "flags": [
              "little_endian"
            ]
          }
        }
      ]
    },
    {
      "name": "dce_stub_data",
      "direction": "toserver",
      "is_mpm": true,
      "app_proto": "smb",
      "progress": 0,
      "matches": [
        {
          "name": "content",
          "content": {
            "pattern": "abc",
            "length": 3,
            "nocase": false,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "no_double_inspect": false,
            "fast_pattern": false,
            "relative_next": true
          }
        },
        {
          "name": "byte_extract"
        },
        {
          "name": "byte_test",
          "byte_test": {
            "nbytes": 4,
            "offset": 4,
            "base": "unset",
            "flags": [
              "little_endian"
            ]
          }
        }
      ]
    }
  ],
  "lists": {},
  "mpm": {
    "buffer": "dce_stub_data",
    "pattern": "abc",
    "length": 3,
    "nocase": false,
    "negated": false,
    "starts_with": false,
    "ends_with": false,
    "is_mpm": true,
    "no_double_inspect": false,
    "fast_pattern": false,
    "relative_next": true
  }
}

8.53.4. Detailed Flowcharts

A look into the illustrated overall representation of functions or paths that determine signature types.
8.53.4.1. IP Only and IP Only with negated addresses

ip_only and like_ip_only flows.
A flowchart representing the SignatureIsIPOnly function.
8.53.4.2. Protocol Detection Only

pd_only flow.
A flowchart representing the SignatureIsPDOnly function.
8.53.4.3. Application Layer Protocol, Transaction, Packet, Stream and Stream-Packet rules

app_layer, app_tx, pkt, stream and stream-pkt flows.

REQUIRE_PACKET_ and REQUIRE_STREAM can be seen as flags need_packet and need_stream in the engine-analysis output.
A flowchart representing the portion of SignatureSetType function that handles app_layer, app_tx, stream, pkt_stream and pkt rules.

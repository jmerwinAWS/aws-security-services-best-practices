Anatomy of Suricata Rules

Before diving into the different strategies for writing your best Suricata rules, let’s start off by dissecting an example Suricata Rule:

alert tcp $EXTERNAL_NET any -> 10.200.0.0/24 80 (msg:"WEB-IIS CodeRed v2 root.exe access"; flow:to_server,established; uricontent:"/root.exe"; nocase; classtype:web application-attack; reference:url,www.cert.org/advisories/CA-2001 19.html; sid:1255; rev:7;)

alert: tells Suricata to report this behavior as an alert (it’s mandatory in rules created for the STA).

tcp: means that this rule will only apply to traffic in TCP.

$EXTERNAL_NET: this is a variable defined in Suricata. By default, the variable HOME_NET is defined as any IP within these ranges: 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 and EXTERNAL_NET is defined as any IP outside of these ranges. You can specify IP addresses either by specifying a single IP like 10.200.0.0, an IP CIDR range like 192.168.0.0/16 or a list of IPs like [192.168.0.0/16,10.0.0.0/8]. Just note that spaces within the list are not allowed.

any: in this context, it means “from any source port”, then there’s an arrow ‘->’ which means “a connection to” (there isn’t a ‘<-‘ operator, but you can simply flip the arguments around the operator. You can use the ‘<>’ operator to indicate that the connection direction is irrelevant for this rule), then an IP range which indicates the destination IP address and then the port. You can indicate a port range by using colon like 0:1024 which means 0-1024. In the round parenthesis, there are some directives for setting the alert message, metadata about the rule, as well as additional checks.

msg: is a directive that simply sets the message that will be sent (to Coralogix in the STA case) in case a matching traffic will be detected.

flow: is a directive that indicates whether the content we’re about to define as our signature needs to appear in the communication to the server (“to_server”) or to the client (“to_client”). This can be very useful if, for example, we’d like to detect the server response that indicates that it has been breached.

established: is a directive that will cause Suricata to limit its search for packets matching this signature to packets that are part of established connections only. This is useful to minimize the load on Suricata.

uricontent: is a directive that instructs Suricata to look for a certain text in the normalized HTTP URI content. In this example, we’re looking for a url that is exactly the text “/root.exe”.

nocase: is a directive that indicates that we’d like Suricata to conduct a case insensitive search.

classtype: is a directive that is a metadata attribute indicating which type of activity this rule detects.

reference: is a directive that is a metadata attribute that links to another system for more information. In our example, the value url,<https://….> links to a URL on the Internet.

sid: is a directive that is a metadata attribute that indicates the signature ID. If you are creating your own signature (even if you’re just replacing a built-in rule), use a value above 9,000,000 to prevent a collision with another pre-existing rule.

rev: is a directive that indicates the version of the rule.

There’s a lot more to learn about Suricata rules which supports RegEx parsing, protocol-specific parsing (just like uricontent for HTTP), looking for binary (non-textual) data by using bytes hex values, and much much more. If you’d like to know more you can start here.

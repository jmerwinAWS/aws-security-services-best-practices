
8.42. Thresholding Keywords

Thresholding can be configured per rule and also globally, see Global-Thresholds.

Thresholds are tracked in a hash table that is sized according to configuration, see: Thresholding Settings.

IMPORTANT for both threshold and detection_filter keywords

Note

Rules that contain flowbits, flowints, etc will still have those actions performed when the rule contains one of the threshold keywords. Those actions are not subject to the threshold limits.

Rule actions drop (IPS mode) and reject are applied to each packet (not only the one that meets the limit condition).
8.42.1. threshold

The threshold keyword can be used to control the rule's alert frequency. There are four threshold modes:

    threshold

    limit

    both

    backoff

Syntax:

threshold: type <threshold|limit|both|backoff>, track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, <seconds <T>|multiplier <M>>

Specify seconds to control the number of alerts per time period.
8.42.1.1. type "threshold"

This type sets a minimum threshold for a rule before it generates alerts.

A threshold setting with a count value of C will generate an alert the Cth time the alert matches. If seconds is specified, an alert is generated when count matches have occurred within N seconds.

Syntax:

threshold: type threshold, track by_flow, count <C>, seconds <N>;

Example:

alert tcp !$HOME_NET any -> $HOME_NET 25 (msg:"ET POLICY Inbound Frequent Emails - Possible Spambot Inbound"; flow:established; content:"mail from|3a|"; nocase; threshold: type threshold, track by_src, count 10, seconds 60; reference:url,doc.emergingthreats.net/2002087; classtype:misc-activity; sid:2002087; rev:10;)

This signature generates an alert if there are 10 or more inbound emails from the same server within one minute.
8.42.1.2. type "limit"

The limit type prevents a flood of alerts by limiting the number of alerts. A limit with a count of N won't generate more than N alerts.

Limit the number of alerts per time period by specifying seconds with count.

Syntax:

threshold: type limit, track by_dst, count <C>, seconds <N>;

Example:

alert http $HOME_NET any -> any any (msg:"ET INFO Internet Explorer 6 in use - Significant Security Risk"; flow:established,to_server; http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 6.0|3b|"; threshold: type limit, track by_src, seconds 180, count 1; classtype:policy-violation; sid:2010706; rev:10; metadata:created_at 2010_07_30, updated_at 2024_03_16;)

In this example, at most 1 alert is generated per host within a period of 3 minutes if "MSIE 6.0" is detected.
8.42.1.3. type "both"

This type combines threshold and limit to control when alerts are generated.

Syntax:

threshold: type both, track by_flow, count <C>, multiplier <M>;

Example:

alert tcp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses TCP"; flow:established,from_server; content:"SIP/2.0 401 Unauthorized"; depth:24; threshold: type both, track by_src, count 5, seconds 360; reference:url,doc.emergingthreats.net/2003194; classtype:attempted-dos; sid:2003194; rev:6;)

This rule will generate at most one alert every 6 minutes if there have been 5 or more occurrences of "SIP2.0 401 Unauthorized" responses.

The type backoff section describes the multiplier keyword.
8.42.1.4. type "backoff"

This type limits the alert output by using a backoff algorithm between alerts.

Note

backoff can only be used with track by_flow

Syntax:

threshold: type backoff, track by_flow, count <C>, multiplier <M>;

track: backoff is only supported for by_flow count: number of alerts before the first match generates an alert. multiplier: value to multiply count with each time the next value is reached

A count of 1 with a multiplier of 10 would generate alerts for matching packets:

1, 10, 100, 1000, 10000, 100000, etc.

A count of 1 with a multiplier of 2 would generate alerts for matching packets:

1, 2, 4, 8, 16, 32, 64, etc.

A count of 5 with multiplier 5 would generate alerts for matching packets:

5, 25, 125, 625, 3125, 15625, etc

In the following example, the pkt_invalid_ack would only lead to alerts the 1st, 10th, 100th, etc.

alert tcp any any -> any any (stream-event:pkt_invalid_ack; threshold:type backoff, track by_flow, count 1, multiplier 10; sid:2210045; rev:2;)
8.42.1.5. track

Option
	

Tracks By

by_src
	

source IP

by_dst
	

destination IP

by_both
	

pair of src IP and dst IP

by_rule
	

signature id

by_flow
	

flow
8.42.2. detection_filter

The detection_filter keyword can be used to alert on every match after an initial threshold has been reached. It differs from threshold with type threshold in that it generates an alert for each rule match after the initial threshold has been reached, where the latter will reset its internal counter and alert each time the threshold has been reached.

Syntax:

detection_filter: track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, seconds <T>

Example:

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebResource.axd access without t (time) parameter - possible ASP padding-oracle exploit"; flow:established,to_server; content:"GET"; http_method; content:"WebResource.axd"; http_uri; nocase; content:!"&t="; http_uri; nocase; content:!"&amp|3b|t="; http_uri; nocase; detection_filter:track by_src,count 15,seconds 2; reference:url,netifera.com/research/; reference:url,www.microsoft.com/technet/security/advisory/2416728.mspx; classtype:web-application-attack; sid:2011807; rev:5;)

This rule will generate alerts after 15 or more matches have occurred within 2 seconds.

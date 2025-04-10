{
   "RuleVariables":{
      "IPSets":{
         "HTTP_SERVERS":{
            "Definition":[
               "10.0.2.0/24",
               "10.0.1.19"
            ]
         }
      },
      "PortSets":{
         "HTTP_PORTS":{
            "Definition":[
               "80",
               "8080"
            ]
         }
      }
   },
   "ReferenceSets":{
      "IPSetReferences":{
         "BETA":{
            "ReferenceArn":"arn:aws:ec2:us-east-1:555555555555:prefix-list/pl-1111111111111111111_beta"
         }
      }
   },
   "RulesSource":{
      "RulesString":"drop tcp @BETA any -> any any (sid:1;)"
   }
}
{
    "RulesSource": {
      "StatefulRules": [
        {
          "Action": "DROP",
          "Header": {
            "DestinationPort": "ANY",
            "Direction": "FORWARD",
            "Destination": "ANY",
            "Source": "ANY",
            "SourcePort": "ANY",
            "Protocol": "IP"
          },
          "RuleOptions": [
            {
              "Settings": [
                "1"
              ],
              "Keyword": "sid"
            },
            {
              "Settings": [
                "src,!US,UK"
              ],
              "Keyword": "geoip"
            }
          ]
        }
      ]
    },
    "StatefulRuleOptions": {
       "RuleOrder": "STRICT_ORDER"
     }
 }
{
    "RulesSource": {
        "RulesSourceList": {
            "Targets": [
                "evil.com"
            ],
            "TargetTypes": [
                 "TLS_SNI",
                 "HTTP_HOST"
             ],
             "GeneratedRulesType": "DENYLIST"
        }
    }
}
#Allow access to any ssm. Server Name Indication (SNI) ending with .amazonaws.com
#Allows access to any domain that begins with ssm. and ends with .amazonaws.com (http://amazonaws.com/).
pass tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"ssm."; startswith; content:".amazonaws.com"; endswith; nocase; flow: to_server; sid:202308311;)
#JA3 hash
#This rule allows outbound access using a specific JA3 hash
pass tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Only allow Curl 7.79.1 JA3"; ja3.hash; content:"27e9c7cc45ae47dc50f51400db8a4099"; sid:12820009;)
#Outbound requests to checkip.amazonaws.com
#These rules only allow outbound requests to the SNI checkip.amazonaws.com (http://checkip.amazonaws.com/) if the server certificate issuer is also Amazon. Requires that your firewall policy uses strict order rule evaluation order.
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (ssl_state:client_hello; tls.sni; content:"checkip.amazonaws.com"; endswith; nocase; xbits:set, allowed_sni_destination_ips, track ip_dst, expire 3600; noalert; sid:238745;)
pass tcp $HOME_NET any -> $EXTERNAL_NET 443 (xbits:isset, allowed_sni_destination_ips, track ip_dst; flow: stateless; sid:89207006;)
pass tls $EXTERNAL_NET 443 -> $HOME_NET any (tls.cert_issuer; content:"Amazon"; msg:"Pass rules do not alert"; xbits:isset, allowed_sni_destination_ips, track ip_src; sid:29822;)
reject tls $EXTERNAL_NET 443 -> $HOME_NET any (tls.cert_issuer; content:"="; nocase; msg:"Block all other cert issuers not allowed by sid:29822"; sid:897972;)
#Outbound SSH/SFTP servers with AWS_SFTP banner
#These rules only allow outbound access to SSH/SFTP servers that have a banner that includes AWS_SFTP, which is the banner for AWS Transfer Family servers. To check for a different banner, replace AWS_SFTP with the banner you want to check for.
pass tcp $HOME_NET any -> $EXTERNAL_NET 22 (flow:stateless; sid:2221382;)
pass ssh $EXTERNAL_NET 22 -> $HOME_NET any (ssh.software; content:"AWS_SFTP"; flow:from_server; sid:217872;)
drop ssh $EXTERNAL_NET 22 -> $HOME_NET any (ssh.software; content:!"@"; pcre:"/[a-z]/i"; msg:"Block unauthorized SFTP/SSH."; flow: from_server; sid:999217872;)
#Send DNS query including .amazonaws.com to external DNS servers
#Send DNS query including .amazonaws.com to external DNS servers
pass dns $HOME_NET any -> $EXTERNAL_NET any (dns.query; dotprefix; content:".amazonaws.com"; endswith; nocase; msg:"Pass rules do not alert"; sid:118947;)
#Connections using TLS versions 1.0 or 1.1
#This rule blocks connections using TLS version 1.0 or 1.1.
reject tls any any -> any any (msg:"TLS 1.0 or 1.1"; ssl_version:tls1.0,tls1.1; sid:2023070518;)
#Multiple CIDR ranges
#This rule blocks outbound access to multiple CIDR ranges in a single rule.
drop ip $HOME_NET any-> [10.10.0.0/16,10.11.0.0/16,10.12.0.0/16] (msg:"Block traffic to multiple CIDRs"; sid:278970;)
#Multiple SNIs
#This rule blocks multiple SNIs with a single rule.
reject tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; pcre:"/(example1\.com|example2\.com)$/i"; flow: to_server; msg:"Domain blocked"; sid:1457;)
#Multiple high-risk destination outbound ports
#This rule blocks multiple high-risk destination outbound ports in a single rule.
drop ip $HOME_NET any -> $EXTERNAL_NET [1389,53,4444,445,135,139,389,3389] (msg:"Deny List High Risk Destination Ports"; sid:278670;)
#Outbound HTTP HOST
#This rule blocks outbound HTTP connections that have an IP address in the HTTP HOST header.
reject http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"IP in HTTP HOST Header (direct to IP, likely no DNS resolution first)"; flow:to_server; sid:1239847;)
#Outbound TLS with IP in SNI
#This rule blocks outbound TLS connections with an IP address in the SNI.
reject tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"IP in TLS SNI (direct to IP, likely no DNS resolution first)"; flow:to_server; sid:1239848;)
#Any IP protocols other than TCP, UDP, and ICMP
#This rule silently blocks any IP protocols other than TCP, UDP, and ICMP.
drop ip any any-> any any (noalert; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; sid:21801620;)
#SSH non-standard ports
#This rule blocks the use of the SSH protocol on non-standard ports.
reject ssh $HOME_NET any -> $EXTERNAL_NET !22 (msg:"Block use of SSH protocol on non-standard port"; flow: to_server; sid:2171010;)
#TCP/22 servers non-SSH
#This rule blocks the use of TCP/22 servers that aren't using the SSH protocol.
reject tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:"Block TCP/22 servers that are not SSH protocol"; flow: to_server; app-layer-protocol:!ssh; sid:2171009;)
#Log traffic direction in default-deny policy
#Can be used at the end of a default-deny policy to accurately log the direction of denied traffic. These rules help you to make it clear in the logs who the client is and who the server is in the connection.
#reject tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Default Egress TCP block to server"; flow:to_server; sid:202308171;)
drop udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Default Egress UDP block";sid:202308172;)
drop icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"Default Egress ICMP block";sid:202308177;)
drop tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Default Ingress block to server"; flow:to_server; sid:20230813;)
drop udp $EXTERNAL_NET any -> $HOME_NET any (msg:"Default Ingress UDP block"; sid:202308174;)
drop icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"Default Ingress ICMP block"; sid:202308179;)
#Log traffic to an allowed SNI.
#These rules log traffic to an allowed SNI. Requires your policy to use strict order rule evaluation order.

#Pingbed begin
#
#GET /default.htm HTTP/1.1\r\n
#User-Agent: Windows+NT+5.1\r\n
#Host: www.trackdia.com\r\n
#Cache-Control: no-cache\r\n
#\r\n
alert tcp any any -> any any (\
	msg:"Pingbed simple rule";\
	content:"GET /default.htm HTTP/1.1|0d 0a|"; offset:0; depth:27;\
	content:"User-Agent: Windows+NT+5.1|0d 0a|"; distance:0; within: 100;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Pingbed_74fc916a0187f3d491ef9fb0b540f228.pcap;\
	sid:1;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"Pingbed suricata rule";\
	http.user_agent; content:"Windows+NT+5.1";\
	http.uri; content:"default.htm";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Pingbed_74fc916a0187f3d491ef9fb0b540f228.pcap;\
	sid:2;\
	rev:1;\
)
#Pingbend end

#Taidoor begin
#
#GET /viswi.php?id=001090111D309GE67E HTTP/1.1\r\n
#User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n
#Host: 211.234.117.141:443\r\n
#Connection: Keep-Alive\r\n
#Cache-Control: no-cache\r\n
#\r\n
alert tcp any any -> any any (\
	msg:"Taidoor simple rule";\
	content:"111D309GE67E"; offset:24; depth:12;\
	pcre:"/^GET \/[a-z]{5}\.php\?id=[0-9]{6}111D309GE67E HTTP\/1.1/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taidoor_40D79D1120638688AC7D9497CC819462_2012-10.pcap;\
	sid:3;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"Taidoor suricata rule";\
	http.uri; content:"111D309GE67E"; pcre:"/^\/[a-z]{5}\.php\?id=[0-9]{6}111D309GE67E$/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taidoor_40D79D1120638688AC7D9497CC819462_2012-10.pcap;\
	sid:4;\
	rev:1;\
)
#Taidoor end

#Gh0st-gif begin
#
#GET /h.gif?pid =113&v=130586214568 HTTP/1.1\r\n
#Accept: */*\r\n
#Accept-Language: en-us\r\n
#Pragma: no-cache\r\n
#User-Agent: Mozilla/4.0(compatible; MSIE 6.0; Windows NT 5.1)\r\n
#Connection: Keep-Alive\r\n
#\r\n
alert tcp any any -> any any (\
	msg:"Gh0st-gif simple rule";\
	content:"GET /h.gif?pid ="; offset:0; depth:16;\
	content:"&v="; distance:3; within:3;\
	pcre:"/^GET \/h\.gif\?pid =[0-9]{3}&v=[0-9]{12} HTTP\/1\.1/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Gh0st-gif_f4d4076dff760eb92e4ae559c2dc4525.pcap;\
	sid:5;\
	rev:1;\
)

#Currently, http.uri has a bug with parsing uris with spaces on them. See https://redmine.openinfosecfoundation.org/issues/2881
alert http any any -> any any (\
	msg:"Gh0st-gif suricata rule";\
	http.request_line; content:"/h.gif?pid ="; content:"&v="; distance:3; within:3; pcre:"/^GET \/h\.gif\?pid =[0-9]{3}&v=[0-9]{12} HTTP\/1\.1$/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Gh0st-gif_f4d4076dff760eb92e4ae559c2dc4525.pcap;\
	sid:6;\
	rev:1;\
)
#Gh0st-gif end

#Hupigon begin
##TODO: Finish hupigon after dealing with https://forum.suricata.io/t/different-behaviour-between-byte-test-and-content-when-using-flowbits/1361
#
#Packet 1:
#0000   00 00 00 00
#
#Packet 2:
#0000   c1 d6 c1 d6 c9 cf cf df d6 f7 bb fa 00 00 00 00
#0010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0020   0c 00 00 00 3b 00 00 00 57 69 6e 64 6f 77 73 20
#0030   58 50 20 35 2e 31 20 28 32 36 30 30 2e 53 65 72
#0040   76 69 63 65 20 50 61 63 6b 20 33 29 00 00 00 00
#0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0080   00 00 00 00 00 00 00 00 00 00 00 00 24 00 00 00
#0090   44 45 4c 4c 58 54 00 00 00 00 00 00 00 00 00 00
#00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#00d0   06 00 00 00 c1 d6 c1 d6 c9 cf cf df d6 f7 bb fa
#00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#00f0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0100   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#0110   0c 00 00 00 34 73 2e 6c 6f 76 65 00 00 00 00 00
#0120   00 00 48 41 43 4b 00 00
#
#Profiling: sid 7 performed quite poorly before adding prefilter. I guess suricata 6.x doesn't automatically pick a prefiltering criteria unless there is a content term, resulting in this rule having to be evaluated against every packet. 
alert tcp any any -> any any (\
	msg:"Hupigon suricata rule - connection setup byte_test (works)";\
	dsize:4; prefilter;\
	byte_test:4,=,0,0;\
	flowbits:set,hupigon.start;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Hupigon_8F90057AB244BD8B612CD09F566EAC0C.pcap;\
	sid:7;\
	rev:1;\
)

alert tcp any any -> any any (\
	msg:"Hupigon suricata rule - connection setup content (works)";\
	dsize:4;\
	content:"|00 00 00 00|"; offset:0; depth:4;\
	flowbits:set,hupigon.start;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Hupigon_8F90057AB244BD8B612CD09F566EAC0C.pcap;\
	sid:8;\
	rev:1;\
)

#Note that byte_extract can only handle 8 bytes in non string mode. There are actually 12 static bytes here
alert tcp any any -> any any (\
	msg:"Hupigon suricata rule - beacon byte_test offset 4 (should not work but does)";\
	byte_test:8,=,0xc1d6c1d6c9cfcfdf,4;\
	flowbits:isset,hupigon.start;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Hupigon_8F90057AB244BD8B612CD09F566EAC0C.pcap;\
	sid:9;\
	rev:1;\
)

alert tcp any any -> any any (\
	msg:"Hupigon suricata rule - beacon byte_test offset 0 (does not work)";\
	byte_test:8,=,0xc1d6c1d6c9cfcfdf,0;\
	flowbits:isset,hupigon.start;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Hupigon_8F90057AB244BD8B612CD09F566EAC0C.pcap;\
	sid:10;\
	rev:1;\
)

alert tcp any any -> any any (\
	msg:"Hupigon suricata rule - beacon content offset 0 (works)";\
	flowbits:isset,hupigon.start;\
	byte_test:8,=,0xc1d6c1d6c9cfcfdf,0;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Hupigon_8F90057AB244BD8B612CD09F566EAC0C.pcap;\
	sid:11;\
	rev:1;\
)

#Hupigon end
#	flowbits:isnotset,hupigon.start;\
#	flowbits:noalert;\
#	byte_test:8,=,0xc1d6c1d6c9cfcfdf,0;\
#	byte_test:8,=,0xc1d6c1d6c9cfcfdf,212;\
#	content:"|c1 d6 c1 d6 c9 cf cf df|"; offset:212; depth:8;\
	#	byte_extract:8,0,hupigon.static_bytes;\
	#	byte_test:8,=,hupigon.static_bytes,212;\
	#


#Enfal_lurid begin
#NOTE: This ja3 is also shared by the TrojanPage pcap. It might reflect the sandbox and not the malware itself
alert tls any any -> any any (\
	msg:"Enfal_lurid suricata rule";\
	ja3.hash; content:"de350869b8c85de67a350c8d186f11e6";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Enfal_Lurid_0fb1b0833f723682346041d72ed112f9_2013-01.pcap;\
	sid:12;\
	rev:1;\
)
#Enfal_lurid end

#Tapaoux begin
#
#GET /ol/yahoo/banner3.php?jpg=../(L2xq1Q3)/(eGAz1DMtdmlydGVhbDBx/(MSAfMSUcWzIyWzHc HTTP/1.1\r\n
#User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1;)\r\n
#Host: re.policy-forums.org\r\n
#\r\n
#
#POST /ol/yahoo/banner1.php HTTP/1.1\r\n
#Accept: */*\r\n
#Content-Type: multipart/form-data; boundary=7d13a23b368\r\n
#User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1;)\r\n
#Host: re.policy-forums.org\r\n
#Content-Length: 361\r\n
#Connection: Keep-Alive\r\n
#Cache-Control: no-cache\r\n
#\r\n\r\n
#--7d13a23b368
#Content-Disposition: form-data; name="dirname"
#
#../(L2xq1Q3)/(eGAz1DMtdmlydGVhbDBx/(MSAfMSUcWzIyWzHc
#--7d13a23b368
#Content-Disposition: form-data; name="userfile"; filename="C:\WINDOWS\system32\ffffz201108231053ca.tmp"
#Content-Type: application/octet-stream
#
#-%&%fx#<'! 49ed.<; .ngceen.0'#<60u.46>uf}f{e|nde
#d``
#gg
#l`o
#--7d13a23b368--
alert tcp any any -> any any (\
	msg:"Tapaoux simple rule GET";\
	content:"GET /ol/yahoo/banner"; offset:0; depth:20;\
	content:".php?jpg=../"; distance:1; within:12;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Tapaoux_60AF79FB0BD2C9F33375035609C931CB_winver_2011-08-23.pcap;\
	sid:13;\
	rev:1;\
)

alert tcp any any -> any any (\
	msg:"Tapaoux simple rule POST";\
	content:"POST /ol/yahoo/banner"; offset:0; depth:21;\
	content:".php"; distance:1; within:4;\
	content:"Content-Disposition: form-data|3b| name=|22|dirname|22 0d 0a 0d 0a|../"; distance:0;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Tapaoux_60AF79FB0BD2C9F33375035609C931CB_winver_2011-08-23.pcap;\
	sid:14;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"Tapaoux suricata rule GET";\
	http.method; content:"GET";\
	http.uri; content:"/ol/yahoo/banner"; content:".php?jpg=../"; distance:1; within:12;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Tapaoux_60AF79FB0BD2C9F33375035609C931CB_winver_2011-08-23.pcap;\
	sid:15;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"Tapaoux suricata rule POST";\
	http.method; content:"POST";\
	http.uri; content:"/ol/yahoo/banner"; content:".php"; distance:1; within:4;\
	http.request_body; content:"Content-Disposition: form-data|3b| name=|22|dirname|22 0d 0a 0d 0a|../";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Tapaoux_60AF79FB0BD2C9F33375035609C931CB_winver_2011-08-23.pcap;\
	sid:16;\
	rev:1;\
)
#Tapaoux end

#IXESHE begin
#
#GET /AWS96.jsp?baQMyZrdI5Rojs9Khs9fhnjwj/8mIOm9jOKyjnxKjQJA HTTP/1.1\r\n
#x_bigfix_client_string: baQMyZrdqDAA\r\n
#User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\r\n
#Host: freedream.strangled.net:443\r\n
#Connection: Keep-Alive\r\n
#\r\n
alert tcp any any -> any any (\
	msg:"IXESHE simple rule";\
	content:"GET /AWS96.jsp"; offset:0; depth:14;\
	content:"x_bigfix_client_string"; distance:2;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_IXESHE_0F88D9B0D237B5FCDC0F985A548254F2-2013-05.pcap;\
	sid:17;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"IXESHE suricata rule";\
	http.uri; content:"/AWS96.jsp";\
	http.header_names; content:"|0d 0a|x_bigfix_client_string|0d 0a|";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_IXESHE_0F88D9B0D237B5FCDC0F985A548254F2-2013-05.pcap;\
	sid:18;\
	rev:1;\
)
#IXESHE end

#Darkcomet begin
#The id= parameter seems to be a base64 encoded email address. Assuming the absolute smallest email address looks like a@b.c results in a minimum base64 length of 8 chars
#base64_decode is given a large number of bytes, since decoding will end at the end of the buffer anyway
#I tried combing pcrexform with base64_decode, but base64_decode doesn't seem to want to use the output buffer from pcrexform
#
#GET /a.php?id=c2ViYWxpQGxpYmVyby5pdA== HTTP/1.1\r\n
#Host: 64.235.43.131\r\n
#\r\n
#
#Profiling: This rule performs poorly, both in ticks_total and in ticks_avg. This is due to the limited filtering and expensive (base64_data) check. In testing, changing the number of bytes that base64_decode uses does not significantly affect performance.
alert http any any -> any any (\
	msg:"Darkcomet suricata rule";\
	http.method; content:"GET";\
	urilen:>16;\
	http.uri; content:"id="; base64_decode: bytes 500, offset 0, relative;\
	base64_data; content:"@";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Darkcomet_DC98ABBA995771480AECF4769A88756E.pcap;\
	sid:19;\
	rev:1;\
)
#Darkcomet end

#TrojanCookies begin
#
#GET / HTTP/1.1 \r\n
#Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n
#Set-Cookie: AS8/TFljcH2HlJ6ruMLP3OagBt1Zmjp4X55af58gJxG+vcRg/1bdnmNT96EErJD7bfWH735hK5UgHki5DpK2KXz4QRzThUeOQYLtgDqH0hf0azTU65DDa/LfP44aaH7DMaUIFepiefAmDIWW+B4YgGoksrzb4NX6sW4jvO+XMDJ3YrmnqR/feSIYv/tPcmFOaQAA\r\n
#Accept-Language: en-us\r\n
#Accept-Encoding: gzip, deflate\r\n
#User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n
#Host: 184.22.41.10\r\n
#Connection: Keep-Alive\r\n
#Cache-Control: no-cache\r\n
#\r\n
alert tcp any any -> any any (\
	msg:"TrojanCookies simple rule";\
	content:"GET /"; offset:0; depth:5;\
	content:"Set-Cookie: "; distance:0;\
	content:"Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT 5.1)"; distance:100;\
	pcre:"/Set-Cookie: [a-zA-Z0-9+/]{100,}/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_TrojanCookies_840BD11343D140916F45223BA05ABACB_2012_01.pcap;\
	sid:20;\
	rev:1;\
)

alert http any any -> any any (\
	msg:"TrojanCookies suricata rule";\
	flow:established,to_server;\
	http.header_names; content:"|0d 0a|Set-Cookie|0d 0a|";\
	http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT 5.1)";\
	http.header; pcre:"/Set-Cookie: [a-zA-Z0-9+/]{100,}/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_TrojanCookies_840BD11343D140916F45223BA05ABACB_2012_01.pcap;\
	sid:21;\
	rev:1;\
)
#TrojanCookies end

#Xinmic begin
#
#Handshake
# 0000   14 00 00 00 00 00 00 00 00 00 06 3e
#
#Beacon
# 0000   13 10 05 00 02 00 00 00

alert tcp any any -> any any (\
	msg:"Xinmic simple rule - handshake";\
	content:"|14 00 00 00 00 00 00 00 00 00 06 3e|"; offset:0; depth:12;\
	dsize:12;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Xinmic_8761F29AF1AE2D6FACD0AE5F487484A5.pcap;\
	sid:22;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"Xinmic simple rule - beacon";\
	content:"|13 10 05 00 02 00 00 00|"; offset:0; depth:8;\
	dsize:8;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Xinmic_8761F29AF1AE2D6FACD0AE5F487484A5.pcap;\
	sid:23;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"Xinmic suricata rule - handshake";\
	content:"|14 00 00 00 00 00 00 00 00 00 06 3e|"; offset:0; depth:12;\
	dsize:12;\
	flowbits:set,xinmic.handshake;\
	flowbits:noalert;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Xinmic_8761F29AF1AE2D6FACD0AE5F487484A5.pcap;\
	sid:24;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"Xinmic suricata rule - beacon";\
	content:"|13 10 05 00 02 00 00 00|"; offset:0; depth:8;\
	dsize:8;\
	flowbits:isset,xinmic.handshake;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Xinmic_8761F29AF1AE2D6FACD0AE5F487484A5.pcap;\
	sid:25;\
	rev:1;\
	)
#Xinmic end

#NJRat begin
#
#Example 1
# 0000   02 00 00 00 a2 00
#
#Example 2
# 0000   fc 0f 00 00 a0 32 30 31 33 30 38 31 39 b2 d8 b6   .....20130819...
# 0010   c0 7c 28 31 37 32 2e 31 36 2e 32 35 33 2e 31 33   .|(172.16.253.13
# 0020   32 29 7c 31 30 34 36 7c 57 69 6e 58 50 7c 44 7c   2)|1046|WinXP|D|
# 0030   4c 7c 4e 6f 7c 30 cc ec 30 d0 a1 ca b1 30 b7 d6   L|No|0..0....0..
# 0040   30 c3 eb 7c 4e 6f 7c 56 32 30 31 30 2d 76 32 34   0..|No|V2010-v24
# 0050   7c 36 36 38 7c 30 7c 35 61 66 32 39 38 65 66 7c   |668|0|5af298ef|
# 0060   30 7c 30 7c 00 00 00 00 00 00 00 00 00 00 00 00   0|0|............
# ... (all nulls)
# 05a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
# 05b0   00 00 00 00                                       ....

alert tcp any any -> any any (\
	msg:"NJRat simple rule - beacon";\
	dsize:6;\
	content:"|02 00 00 00 a2 00|"; offset:0; depth:6;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_NJRat-BackdoorLV_6fd868e68037040c94215566852230ab_CNtiananmensquare.pcap;\
	sid:26;\
	rev:1;\
	)

alert tcp-pkt any any -> any any (\
	msg:"NJRat suricata rule - host info";\
	content:"20"; offset:5; depth:2;\
	byte_test:4, >=, 2010, 5, string, dec;\
	byte_test:4, <=, 2030, 5, string, dec;\
	byte_test:2, >=, 1, 9, string, dec;\
	byte_test:2, <=, 12, 9, string, dec;\
	byte_test:2, >=, 1, 11, string, dec;\
	byte_test:2, <=, 31, 11, string, dec;\
	pcre:"/^.{5}20[1-3][0-9][01][0-9][0-3][0-9]/";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_NJRat-BackdoorLV_6fd868e68037040c94215566852230ab_CNtiananmensquare.pcap;\
	sid:27;\
	rev:1;\
	)
#NJRat end

#Taleret.E begin
#    GET /jw!Dyz0_2mTExQ0xbBnlp.RZcXoHmU- HTTP/1.1\r\n
#    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)\r\n
#    Host: tw.myblog.yahoo.com\r\n
#    Connection: Keep-Alive\r\n
#    Cache-Control: no-cache\r\n
#    Cookie: B=8sah02d6on6k9&b=3&s=as\r\n
#    \r\n
#
#    GET / HTTP/1.1\r\n
#    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n
#    Host: mac.gov.skies.tw\r\n
#    Connection: Keep-Alive\r\n
#    Cache-Control: no-cache\r\n
#    Cookie: MCI=HHMHMBLHEHNLIOJRINRIJPRJIJ; MUID=ba2c08421000e9621000355b0000\r\n
#    \r\n

alert tcp any any -> any any (\
	msg:"Taleret.E simple rule - random url";\
	content:"GET /"; offset:0; depth:5;\
	content:"Cookie: B="; distance:50;\
	content:"&b="; distance:10; within:8;\
	content:"&s="; distance:1; within:5;\
	content:"|0d 0a 0d 0a|"; distance:0; within:7;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taleret.E_5328cfcb46ef18ecf7ba0d21a7adc02c.pcap;\ 
	sid:28;\
	rev:1;\
	)

#Profiling - Adding the user_agent here really improved performance due to how uncommon this user agent is in my pcap samples.
alert http any any -> any any (\
	msg:"Taleret.E suricata rule - random url";\
	http.method; content:"GET";\
	http.cookie; content:"B="; offset:0; depth:2; content:"&b="; distance:10; within:8; content:"&s="; distance:1; within:5;\
	http.header_names; content:"|0d 0a|Cookie|0d 0a 0d 0a|";\
	http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 6.0|3b| Win32)"; isdataat:!1, relative;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taleret.E_5328cfcb46ef18ecf7ba0d21a7adc02c.pcap;\ 
	sid:29;\
	rev:1;\
	)

alert tcp any any -> any 443 (\
	msg:"Taleret.E simple rule - http to port 443";\
	content:"GET / HTTP/1.1"; offset:0; depth:14;\
	content:"Cookie: MCI="; distance:50;\
	content:"|3b| MUID="; distance:26; within:7;\
	content:"|0d 0a 0d 0a|"; distance:28; within:4;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taleret.E_5328cfcb46ef18ecf7ba0d21a7adc02c.pcap;\ 
	sid:30;\
	rev:1;\
	)

alert http any any -> any 443 (\
	msg:"Taleret.E suricata rule - http to port 443";\
	http.method; content:"GET";\
	http.cookie; content:"MCI="; offset:0; depth:4; content:"|3b| MUID="; distance:26; within:7;\
	http.header_names; content:"|0d 0a|Cookie|0d 0a 0d 0a|";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Taleret.E_5328cfcb46ef18ecf7ba0d21a7adc02c.pcap;\ 
	sid:31;\
	rev:1;\
	)
#Taleret.E end

#LURK begin
#
# Client beacon
# 0000   4c 55 52 4b 30 97 00 00 00 94 05 00 00 78 9c 6b   LURK0........x.k
# 0010   66 f0 65 f0 61 70 67 70 62 70 61 30 63 18 05 23   f.e.apgpbpa0c..#
# 0020   19 ac 11 f8 db e2 c2 e0 0a 4c 0f 3e 0c 11 0c 21   .........L.>...!
# 0030   60 31 2e 06 66 86 72 46 0e 86 a2 d4 bc 94 fc 24   `1..f.rF.......$
# 0040   ea d8 23 c3 c8 c0 c0 0a a4 81 14 83 06 17 03 03   ..#.............
# 0050   13 90 0e 66 48 65 28 62 28 63 c8 64 48 06 b2 14   ...fHe(b(c.dH...
# 0060   18 02 18 12 81 ac 6c 20 cb 98 3a 96 0e 72 c0 0c   ......l ..:..r..
# 0070   22 18 19 81 21 9f c8 50 0a 0c 89 c4 81 76 d0 00   "...!..P.....v..
# 0080   81 56 60 7a 30 64 30 60 30 02 c6 bb 2f b0 54 1a   .V`z0d0`0.../.T.
# 0090   89 00 00 84 67 12 29                              ....g.)
# 
# Server Response
# 0000   4c 55 52 4b 30 16 00 00 00 01 00 00 00 78 9c 63   LURK0........x.c
# 0010   00 00 00 01 00 01                                 ......

alert tcp any any -> any any (\
	msg:"LURK simple rule";\
	content:"LURK"; offset:0; depth:4;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_LURK_AF4E8D4BE4481D0420CCF1C00792F484_20120-10.pcap;\ 
	sid:32;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"LURK suricata rule - beacon";\
	content:"LURK"; offset:0; depth:4;\
	flow:established,to_server;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_LURK_AF4E8D4BE4481D0420CCF1C00792F484_20120-10.pcap;\ 
	sid:33;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"LURK suricata rule - response";\
	content:"LURK"; offset:0; depth:4;\
	flow:established,to_client;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_LURK_AF4E8D4BE4481D0420CCF1C00792F484_20120-10.pcap;\ 
	sid:34;\
	rev:1;\
	)
#LURK end

#DNSWatch begin
#
#    POST http://vcvcvcvc.dyndns.org:8080/index.pl ?id=21410 HTTP/1.1\r\n
#    User-Agent: Mozilla/4.8.20 (compatible; MSIE 5.0.2; Win32)\r\n
#    Content-Type: multipart/form-data; boundary=----------2B9250BB47EE537B\r\n
#    Host: vcvcvcvc.dyndns.org \r\n
#    Content-Length: 208\r\n
#    Proxy-Connection: keep-alive\r\n
#    Pragma: no-cache\r\n
#    \r\n
#
# Payload
# 0000   2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 32 42 39 32 35 30   ----------2B9250
# 0010   42 42 34 37 45 45 35 33 37 42 0d 0a 43 6f 6e 74   BB47EE537B..Cont
# 0020   65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a   ent-Disposition:
# 0030   20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65    form-data; name
# 0040   3d 22 55 70 6c 6f 61 64 46 69 6c 65 22 3b 20 66   ="UploadFile"; f
# 0050   69 6c 65 6e 61 6d 65 3d 22 31 36 31 44 33 46 43   ilename="161D3FC
# 0060   33 2e 70 6e 67 22 0d 0a 43 6f 6e 74 65 6e 74 2d   3.png"..Content-
# 0070   54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f   Type: applicatio
# 0080   6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 0d 0a   n/octet-stream..
# 0090   0d 0a 01 6e 65 77 5f 68 6f 73 74 5f 34 39 00 00   ...new_host_49..
# 00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
# 00b0   00 00 0d 0a 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 32 42   ....----------2B
# 00c0   39 32 35 30 42 42 34 37 45 45 35 33 37 42 2d 2d   9250BB47EE537B--

alert tcp any any -> any any (\
	msg:"DNSWatch simple rule";\
	content:"POST http://"; offset:0; depth:12;\
	content:"User-Agent: Mozilla/4.8.20 (compatible|3b| MSIE 5.0.2|3b| Win32)|0d 0a|"; distance:0;\
	content:"----------2B9250BB47EE537B|0d 0a|"; distance:0;\
	content:"new_host_"; distance:0;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_DNSWatch_protux_4F8A44EF66384CCFAB737C8D7ADB4BB8_2012-11.pcap;\ 
	sid:35;\
	rev:1;\
	)
#No suricata rule because the protocol is such garbage that it suricata doesn't recognize it as http at all
#DNSWatch end

#Lagulon begin
#
#    POST /i/server.php HTTP/1.1\r\n
#    Content-Disposition: inline; comp=TEQUILABOOMBOOM; account=janettedoe; product=3;\r\n
#    User-Agent: Mozilla/5.0\r\n
#    Host: www.asiess.com\r\n
#    Content-Length: 0\r\n
#    Cache-Control: no-cache\r\n
#    \r\n

alert tcp any any -> any any (\
	msg:"Lagulon simple rule";\
	content:"POST /"; offset:0; depth:6;\
	content:"/server.php HTTP/1.1"; distance:1; within:30;\
	content:"Content-Disposition: inline|3b| comp="; distance:0;\
	content:"|3b| account="; distance:1;\
	content:"|3b| product="; distance:1;\
	content:"User-Agent: Mozilla/5.0|0d 0a|";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Lagulon_e8b1f23616f9d8493e8a1bf0ca0f512a.pcap;\
	sid:36;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"Lagulon suricata rule";\
	flow:established,to_server;\
	http.method; content:"POST";\
	http.uri; content:"/server.php";\
	http.header; content:"Content-Disposition: inline|3b| comp="; content:"|3b| account="; distance:1; content:"|3b| product="; distance:1;\
	http.user_agent; content:"Mozilla/5.0"; isdataat:!1, relative;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Lagulon_e8b1f23616f9d8493e8a1bf0ca0f512a.pcap;\
	sid:37;\
	rev:1;\
	)
#Lagulon end

#Likseput begin
#
#    GET /index.html HTTP/1.1\r\n
#    User-Agent: 5.1 10:59 DELLXT\Laura\r\n
#    Host: nasa.usnewssite.com\r\n
#    Cache-Control: no-cache\r\n
#    \r\n

alert tcp any any -> any any (\
	msg:"Likseput simple rule";\
	content:"User-Agent: 5.1 ";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Likseput_E019E37F19040059AB5662563F06B609_2012-10.pcap;\
	sid:38;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"Likseput suricata rule";\
	http.user_agent; content:"5.1"; offset:0; depth:3;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Likseput_E019E37F19040059AB5662563F06B609_2012-10.pcap;\
	sid:39;\
	rev:1;\
	)
#Likseput end

#Sanny-Daws begin
#
#Username
# 0000   62 57 46 70 62 47 4a 76 62 33 52 6c               bWFpbGJvb3Rl
#
#Password
# 0000   4d 6a 49 7a 4f 44 45 79 0d 0a                     MjIzODEy..

alert tcp any any -> any 25 (\
	msg:"Sanny-Daws simple rule - SMTP password";\
	content:"MjIzODEy|0d 0a|"; offset:0; depth:10;\
	dsize:10;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Sanny-Daws_338D0B855421867732E05399A2D56670_2012-10.pcap;\
	sid:40;\
	rev:1;\
	)

alert smtp any any -> any any (\
	msg:"Sanny-Daws suricata rule - SMTP user";\
	content:"bWFpbGJvb3Rl|0d 0a|"; offset:0; depth:14;\
	dsize:14;\
	flowbits:noalert;\
	flowbits:set,sanny_daws.user;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Sanny-Daws_338D0B855421867732E05399A2D56670_2012-10.pcap;\
	sid:41;\
	rev:1;\
	)

alert smtp any any -> any any (\
	msg:"Sanny-Daws suricata rule - SMTP password";\
	content:"MjIzODEy|0d 0a|"; offset:0; depth:10;\
	dsize:10;\
	flowbits:isset,sanny_daws.user;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Sanny-Daws_338D0B855421867732E05399A2D56670_2012-10.pcap;\
	sid:42;\
	rev:1;\
	)
#Sanny-Daws end

#Mediana begin
#
#    GET http://firewall.happytohell.com:80/index.htm?n763t4OPm*rs6fXq7fXp7uj16e-r&testid HTTP/1.0\r\n
#    Accept: */*\r\n
#    Accept-Language: en-us \r\n
#    Pragma: no-cache \r\n
#    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n
#    Host: firewall.happytohell.com:80 \r\n
#    X-HOST: n763t4OPm*rs6fXq7fXp7uj16e-r \r\n
#    Content-Length: 0 \r\n
#    Proxy-Connection: Keep-Alive \r\n
#    \r\n

alert tcp any any -> any any (\
	msg:"Mediana simple rule";\
	content:"GET http://"; offset:0; depth:11;\
	content:"index.htm?"; distance:0;\
	content:"*"; distance:0;\
	content:"|20|HTTP/1.0";\
	content:"|0d 0a|X-HOST:|20|";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Mediana_0AE47E3261EA0A2DBCE471B28DFFE007_2012-10.pcap;\
	sid:43;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"Mediana suricata rule";\
	http.method; content:"GET";\
	http.protocol; content:"HTTP/1.0";\
	http.header_names; content:"|0d 0a|X-HOST|0d 0a|"; fast_pattern;\
	http.uri.raw; content:"http://"; offset:0; content:"index.htm?"; distance:0; content:"*"; distance:0;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_Mediana_0AE47E3261EA0A2DBCE471B28DFFE007_2012-10.pcap;\
	sid:44;\
	rev:1;\
	)
#Mediana end

#Mswab_Yayih begin
#
# POST /bbs/info.asp HTTP/1.1\r\n
# Host: 199.192.156.134:443\r\n
# Content-Length: 100\r\n
# Connection: Keep-Alive\r\n
# Cache-Control: no-cache\r\n
# \r\n
# <payload>
#
# 0000   50 4f 53 54 20 2f 62 62 73 2f 69 6e 66 6f 2e 61   POST /bbs/info.a
# 0010   73 70 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73   sp HTTP/1.1..Hos
# 0020   74 3a 20 31 39 39 2e 31 39 32 2e 31 35 36 2e 31   t: 199.192.156.1
# 0030   33 34 3a 34 34 33 0d 0a 43 6f 6e 74 65 6e 74 2d   34:443..Content-
# 0040   4c 65 6e 67 74 68 3a 20 31 30 30 0d 0a 43 6f 6e   Length: 100..Con
# 0050   6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c   nection: Keep-Al
# 0060   69 76 65 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72   ive..Cache-Contr
# 0070   6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 0a 0d 0a   ol: no-cache....
# 0080   33 44 33 33 33 35 33 31 35 30 31 41 37 37 37 30   3D333531501A7770
# 0090   61 00 0c 00 48 00 00 00 48 00 00 00 58 50 53 50   a...H...H...XPSP
# 00a0   33 2d 4f 46 43 32 30 30 37 2d 52 7c 75 73 30 33   3-OFC2007-R|us03
# 00b0   30 32 7c 31 30 2e 30 2e 32 2e 31 35 7c 57 69 6e   02|10.0.2.15|Win
# 00c0   4e 54 20 76 35 2e 31 20 62 75 69 6c 64 20 32 36   NT v5.1 build 26
# 00d0   30 30 20 2d 20 53 65 72 76 69 63 65 20 50 61 63   00 - Service Pac
# 00e0   6b 20 33 7c                                       k 3|

alert tcp any any -> any 443 (\
	msg:"Mswab_Yayih simple rule";\
	content:"POST /bbs/info.asp HTTP/1.1"; offset:0; depth:27;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap;\
	sid:45;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"Mswab_Yayih suricata rule";\
	http.method; content:"POST";\
	http.uri; content:"/bbs/info.asp";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap;\
	sid:46;\
	rev:1;\
	)
#Mswab_Yayih end

#8202_tbd begin
#
#The second byte seems to be the length of the payload
#
#Example 1
# 0000   00 0d 00 00 00 00 00 00 00 00 52 00 75            ..........R.u
#
#Example 2
# 0000   07 5a 00 00 00 08 01 01 00 00 00 00 00 05 00 00   .Z..............
# 0010   00 01 00 00 00 01 ac 10 fd 82 18 38 cf 2f 24 e6   ...........8./$.
# 0020   16 43 b5 90 14 17 c1 2e c3 bd 00 06 00 06 00 06   .C..............
# 0030   00 01 00 00 44 00 65 00 6c 00 6c 00 58 00 54 00   ....D.e.l.l.X.T.
# 0040   4c 00 61 00 75 00 72 00 61 00 00 00 38 00 32 00   L.a.u.r.a...8.2.
# 0050   34 00 5f 00 43 00 4c 00 53 00                     4._.C.L.S.
#
#Example 3
# 0000   07 1f 00 00 00 00 00 00 00 00 52 00 75 cd ab 00   ..........R.u...
# 0010   00 01 00 50 00 00 00 00 00 00 00 00 00 04 44      ...P..........D
#
#I have two different rules here as the byte_extract features don't seem to work well when content is used at the same time

alert tcp-pkt any any -> any any (\
	msg:"8202_tbd suricata rule initial beacon content";\
	app-layer-protocol:!http;\
	content:"|00 00 00 00 00 00 00 00 52 00 75|"; offset:2; depth:11;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file 8202_tbd_ 6D2C12085F0018DAEB9C1A53E53FD4D1.pcap;\
	sid:47;\
	rev:1;\
	)

alert tcp-pkt any any -> any any (\
	msg:"8202_tbd suricata rule initial beacon byte_test";\
	app-layer-protocol:!http;\
	byte_test: 8, =, 0x0000000000520075, 5;
	byte_extract: 1, 1, length;\
	isdataat:length;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file 8202_tbd_ 6D2C12085F0018DAEB9C1A53E53FD4D1.pcap;\
	sid:48;\
	rev:1;\
	)

#8202_tbd end

#9002 begin
#
#Example
# 0000   39 30 30 32 10 00 00 00 0c 00 00 00 1d 8c ff b2   9002............
# 0010   01 ff ff ff ff 03 77 78 14 11 00 00               ......wx....

alert tcp any any -> any any (\
	msg:"9002 simple rule";\
	content:"9002"; offset:0; depth:4;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_9002_D4ED654BCDA42576FDDFE03361608CAA_2013-01-30.pcap;\
	sid:49;\
	rev:1;\
	)

#9002 end

#LetsGo_yahoosb begin
#
# GET /index.htm HTTP/1.1\r\n
# User-Agent: IPHONE8.5(host:XPSP3-R93-Ofc2003SP2,ip:172.29.0.116)\r\n
# Accept: */*\r\n
# Host: mickeypluto.info\r\n
# Connection: Keep-Alive\r\n
# \r\n

#fast_pattern is important here as it seems suricata is using "User-Agent: " to prefilter otherwise, resulting in a slower rule
alert tcp any any -> any any (\
	msg:"LetsGo_yahoosb simple rule beacon";\
	content:"User-Agent: ";\
	content:"(host:"; distance:5; fast_pattern;\
	content:",ip:"; distance:5;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_LetsGo_yahoosb_b21ba443726385c11802a8ad731771c0_2011-07-19.pcap;\
	sid:50;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"LetsGo_yahoosb suricata rule beacon";\
	http.user_agent; content:"(host:"; content:",ip:";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_LetsGo_yahoosb_b21ba443726385c11802a8ad731771c0_2011-07-19.pcap;\
	sid:51;\
	rev:1;\
	)
#LetsGo_yahoosb end

#RssFeeder begin
#
# GET /data/rss HTTP/1.1\r\n
# Accept: */*\r\n
# User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5\r\n
# Accept-Encoding: gzip, deflate\r\n
# If-Modified-Since: Thu, 20 Dec 2012 03:31:19 GMT\r\n
# If-None-Match: GgZzyuh3LXs6KS2H9PjPSW1ZUQ\r\n
# Host: huming386.livejournal.com\r\n
# Connection: Keep-Alive\r\n
# \r\n
#
# POST /orange/news.php HTTP/1.1\r\n
# Accept: */*\r\n
# Content-Type: application/x-www-form-urlencoded\r\n
# Accept-Encoding: gzip, deflate\r\n
# User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)\r\n
# Host: killme.98.shoptupian.com\r\n
# Content-Length: 170\r\n
# Connection: Keep-Alive\r\n
# Cache-Control: no-cache\r\n
# \r\n
# cstype=server&authname=servername&authpass=serverpass&hostname=DELLXT&ostype=Microsoft Windows XP Professional3&macaddr=00:0C:29:71:24:89&owner=two13&version=1.2.0&t=4941

alert tcp any any -> any any (\
	msg:"RssFeeder simple rule GET";\
	content:"GET /data/rss HTTP/1.1"; offset:0; depth:22;\
	content:"User-Agent: Mozilla/5.0 (Windows|3b| U|3b| Windows NT 5.1|3b| rv:1.9.1) Gecko/20090624 Firefox/3.5";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_RssFeeder_68EE5FDA371E4AC48DAD7FCB2C94BAC7-2012-06.pcap;\
	sid:52;\
	rev:1;\
	)

alert tcp any any -> any any (\
	msg:"RssFeeder simple rule POST";\
	content:"POST /orange/news.php HTTP/1.1"; offset:0; depth:30;\
	content:"User-Agent: Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT 5.1|3b| Trident/4.0|3b| .NET4.0C|3b| .NET4.0E|3b| .NET CLR 2.0.50727|3b| .NET CLR 3.0.04506.648|3b| .NET CLR 3.5.21022)";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_RssFeeder_68EE5FDA371E4AC48DAD7FCB2C94BAC7-2012-06.pcap;\
	sid:53;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"RssFeeder suricata rule GET";\
	http.method; content:"GET";\
	http.uri; content:"/data/rss";\
	http.user_agent; content:"Mozilla/5.0 (Windows|3b| U|3b| Windows NT 5.1|3b| rv:1.9.1) Gecko/20090624 Firefox/3.5";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_RssFeeder_68EE5FDA371E4AC48DAD7FCB2C94BAC7-2012-06.pcap;\
	sid:54;\
	rev:1;\
	)

alert http any any -> any any (\
	msg:"RssFeeder suricata rule POST";\
	http.method; content:"POST";\
	http.uri; content:"/orange/news.php";\
	http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT 5.1|3b| Trident/4.0|3b| .NET4.0C|3b| .NET4.0E|3b| .NET CLR 2.0.50727|3b| .NET CLR 3.0.04506.648|3b| .NET CLR 3.5.21022)";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file BIN_RssFeeder_68EE5FDA371E4AC48DAD7FCB2C94BAC7-2012-06.pcap;\
	sid:55;\
	rev:1;\
	)
#RssFeeder end

#metasploit_aurora begin
#
#    GET /infowTVeeGDYJWNfsrdrvXiYApnuPoCMjRrSZuKtbVgwuZCXwxKjtEclbPuJPPctcflhsttMRrSyxl.gif HTTP/1.1\r\n
#    Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n
#    Referer: http://192.168.100.202/info?rFfWELUjLJHpP\r\n
#    Accept-Language: en-us\r\n
#    Accept-Encoding: gzip, deflate\r\n
#    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n
#    Host: 192.168.100.202\r\n
#    Connection: Keep-Alive\r\n
#    \r\n

#I profiled 3 variations of the pcre and found that using the R (relative) flag and anchoring it at the start performed better on average than the others:
#pcre:"/^GET \/info[a-zA-Z]{50,100}\.gif HTTP\/1\.1/";
#pcre:"/^GET \/info[a-zA-Z]{50,100}\.gif/";
alert tcp any any -> any any (\
	msg:"metasploit_aurora simple rule GET 3";\
	content:"GET /info"; offset:0;\
	pcre:"/^[a-zA-Z]{50,100}\.gif HTTP\/1\.1/R";\
	content:"Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*|0d 0a|";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file GENERAL_metasploit_aurora_chrissanders.org.pcap;\
	sid:58;\
	rev:1;\
	)
#metasploit_aurora end

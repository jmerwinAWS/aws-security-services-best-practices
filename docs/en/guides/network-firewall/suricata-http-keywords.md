
8.13. HTTP Keywords

Using the HTTP specific sticky buffers (see Modifier Keywords) provides a way to efficiently inspect the specific fields of HTTP protocol communications. After specifying a sticky buffer in a rule it should be followed by one or more Payload Keywords or using pcre (Perl Compatible Regular Expressions).
8.13.1. HTTP Primer

HTTP is considered a client-server or request-response protocol. A client requests resources from a server and a server responds to the request.

In versions of HTTP prior to version 2 a client request could look like:

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

Example signature that would alert on the above request.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/index.html"; bsize:11; http.protocol; content:"HTTP/1.1"; bsize:8; http.user_agent; content:"Mozilla/5.0"; bsize:11; http.host; content:"suricata.io"; bsize:11; classtype:bad-unknown; sid:25; rev:1;)

In versions of HTTP prior to version 2 a server response could look like:

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 258
Date: Thu, 14 Dec 2023 20:22:41 GMT
Server: nginx/0.8.54
Connection: Close

Example signature that would alert on the above response.

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Code Example"; flow:established,to_client; http.stat_code; content:"200"; bsize:8; http.content_type; content:"text/html"; bsize:9; classtype:bad-unknown; sid:30; rev:1;)

Request Keywords:

        file.name

        http.accept

        http.accept_enc

        http.accept_lang

        http.host

        http.host.raw

        http.method

        http.referer

        http.request_body

        http.request_header

        http.request_line

        http.uri

        http.uri.raw

        http.user_agent

        urilen

Response Keywords:

        http.location

        http.response_body

        http.response_header

        http.response_line

        http.server

        http.stat_code

        http.stat_msg

Request or Response Keywords:

        file.data

        http.connection

        http.content_len

        http.content_type

        http.cookie

        http.header

        http.header.raw

        http.header_names

        http.protocol

        http.start

8.13.2. Normalization

There are times when Suricata performs formatting/normalization changes to traffic that is seen.
8.13.2.1. Duplicate Header Names

If there are multiple values for the same header name, they are concatenated with a comma and space (", ") between each value. More information can be found in RFC 2616 https://www.rfc-editor.org/rfc/rfc2616.html#section-4.2

Example Duplicate HTTP Header:

GET / HTTP/1.1
Host: suricata.io
User-Agent: Mozilla/5.0
User-Agent: Chrome/121.0.0

alert http $HOME_NET -> $EXTERNAL_NET (msg:"Example Duplicate Header"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0, Chrome/121.0.0"; classtype:bad-unknown; sid:103; rev:1;)
8.13.3. file.name

The file.name keyword can be used with HTTP requests.

It is possible to use any of the Payload Keywords with the file.name keyword.

Example HTTP Request:

GET /picture.jpg HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP file.name Example"; flow:established,to_client; file.name; content:"picture.jpg"; classtype:bad-unknown; sid:129; rev:1;)

Note

Additional information can be found at File Keywords
8.13.4. http.accept

The http.accept keyword is used to match on the Accept field that can be present in HTTP request headers.

It is possible to use any of the Payload Keywords with the http.accept keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Accept: */*
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept Example"; flow:established,to_server; http.accept; content:"*/*"; bsize:3; classtype:bad-unknown; sid:91; rev:1;)

Note

http.accept does not include the leading space or trailing \r\n

Note

http.accept can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.5. http.accept_enc

The http.accept_enc keyword is used to match on the Accept-Encoding field that can be present in HTTP request headers.

It is possible to use any of the Payload Keywords with the http.accept_enc keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Accept-Encoding: gzip, deflate
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept-Encoding Example"; flow:established,to_server; http.accept_enc; content:"gzip, deflate"; bsize:13; classtype:bad-unknown; sid:92; rev:1;)

Note

http.accept_enc does not include the leading space or trailing \r\n

Note

http.accept_enc can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.6. http.accept_lang

The http.accept_lang keyword is used to match on the Accept-Language field that can be present in HTTP request headers.

It is possible to use any of the Payload Keywords with the http.accept_lang keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Accept-Language: en-US
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept-Encoding Example"; flow:established,to_server; http.accept_lang; content:"en-US"; bsize:5; classtype:bad-unknown; sid:93; rev:1;)

Note

http.accept_lang does not include the leading space or trailing \r\n

Note

http.accept_lang can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.7. http.host

Matching on the HTTP host name has two options in Suricata, the http.host and the http.host.raw sticky buffers.

It is possible to use any of the Payload Keywords with both http.host keywords.

Note

The http.host keyword normalizes the host header contents. If a host name has uppercase characters, those would be changed to lowercase.

Normalization Example:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: SuRiCaTa.Io

In the above example the host buffer would contain suricata.io.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Host Example"; flow:established,to_server; http.host; content:"suricata.io"; bsize:11; classtype:bad-unknown; sid:123; rev:1;)

Note

The nocase keyword is no longer allowed since the host names are normalized to contain only lowercase letters.

Note

http.host does not contain the port associated with the host (i.e. suricata.io:1234). To match on the host and port or negate a host and port use http.host.raw.

Note

http.host does not include the leading space or trailing \r\n

Note

The http.host and http.host.raw buffers are populated from either the URI (if the full URI is present in the request like in a proxy request) or the HTTP Host header. If both are present, the URI is used.

Note

http.host can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.8. http.host.raw

The http.host.raw buffer matches on HTTP host content but does not have any normalization performed on the buffer contents (see http.host)

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: SuRiCaTa.Io:8445

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Host Raw Example"; flow:established,to_server; http.host.raw; content:"SuRiCaTa.Io|3a|8445"; bsize:16; classtype:bad-unknown; sid:124; rev:1;)

Note

http.host.raw does not include the leading space or trailing \r\n

Note

The http.host and http.host.raw buffers are populated from either the URI (if the full URI is present in the request like in a proxy request) or the HTTP Host header. If both are present, the URI is used.

Note

http.host.raw can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.9. http.method

The http.method keyword matches on the method/verb used in an HTTP request. HTTP request methods can be any of the following:

    GET

    POST

    HEAD

    OPTIONS

    PUT

    DELETE

    TRACE

    CONNECT

    PATCH

It is possible to use any of the Payload Keywords with the http.method keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; flow:established,to_server; http.method; content:"GET"; classtype:bad-unknown; sid:2; rev:1;)
8.13.10. http.referer

The http.referer keyword is used to match on the Referer field that can be present in HTTP request headers.

It is possible to use any of the Payload Keywords with the http.referer keyword.

Example HTTP Request:

GET / HTTP/1.1
Host: suricata.io
Referer: https://suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Referer Example"; flow:established,to_server; http.referer; content:"http|3a 2f 2f|suricata.io"; bsize:19; classtype:bad-unknown; sid:200; rev:1;)

Note

http.referer does not include the leading space or trailing \r\n

Note

http.referer can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.11. http.request_body

The http.request_body keyword is used to match on the HTTP request body that can be present in an HTTP request.

It is possible to use any of the Payload Keywords with the http.request_body keyword.

Example HTTP Request:

POST /suricata.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: suricata.io
Content-Length: 23
Connection: Keep-Alive

Suricata request body

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Body Example"; flow:established,to_server; http.request_body; content:"Suricata request body"; classtype:bad-unknown; sid:115; rev:1;)

Note

How much of the request/client body is inspected is controlled in the libhtp configuration section via the request-body-limit setting.

Note

http.request_body replaces the previous keyword name, http_client_body. http_client_body can still be used but it is recommended that rules be converted to use http.request_body.
8.13.12. http.request_header

The http.request_header keyword is used to match on the name and value of a HTTP/1 or HTTP/2 request.

It is possible to use any of the Payload Keywords with the http.request_header keyword.

For HTTP/2, the header name and value get concatenated by ": " (colon and space). The colon and space are commonly noted with the hexadecimal format |3a 20| within signatures.

To detect if an HTTP/2 header name contains a ":" (colon), the keyword http2.header_name can be used.

Example HTTP/1 Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; flow:established,to_server; http.request_header; content:"Host|3a 20|suricata.io"; classtype:bad-unknown; sid:126; rev:1;)

Note

http.request_header does not include the trailing \r\n
8.13.13. http.request_line

The http.request_line keyword is used to match on the entire contents of the HTTP request line.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; flow:established,to_server; http.request_line; content:"GET /index.html HTTP/1.1"; bsize:24; classtype:bad-unknown; sid:60; rev:1;)

Note

http.request_line does not include the trailing \r\n
8.13.14. http.uri

Matching on the HTTP URI buffer has two options in Suricata, the http.uri and the http.uri.raw sticky buffers.

It is possible to use any of the Payload Keywords with both http.uri keywords.

The http.uri keyword normalizes the URI buffer. For example, if a URI has two leading //, Suricata will normalize the URI to a single leading /.

Normalization Example:

GET //index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

In this case //index.html would be normalized to /index.html.

Normalized HTTP Request Example:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP URI Example"; flow:established,to_server; http.uri; content:"/index.html"; bsize:11; classtype:bad-unknown; sid:3; rev:1;)
8.13.15. http.uri.raw

The http.uri.raw buffer matches on HTTP URI content but does not have any normalization performed on the buffer contents. (see http.uri)

Abnormal HTTP Request Example:

GET //index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP URI Raw Example"; flow:established,to_server; http.uri.raw; content:"//index.html"; bsize:12; classtype:bad-unknown; sid:4; rev:1;)

Note

The http.uri.raw keyword/buffer does not allow for spaces.

Example Request:

GET /example spaces HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

http.uri.raw would be populated with /example

http.protocol would be populated with spaces HTTP/1.1

Reference: https://redmine.openinfosecfoundation.org/issues/2881
8.13.16. http.user_agent

The http.user_agent keyword is used to match on the User-Agent field that can be present in HTTP request headers.

It is possible to use any of the Payload Keywords with the http.user_agent keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Cookie: PHPSESSION=123
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP User-Agent Example"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0"; bsize:11; classtype:bad-unknown; sid:90; rev:1;)

Note

http.user_agent does not include the leading space or trailing \r\n

Note

Using the http.user_agent generally provides better performance than using http.header.

Note

http.user_agent can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.17. urilen

The urilen keyword is used to match on the length of the normalized request URI. It is possible to use the < and > operators, which indicate respectively less than and larger than.

urilen uses an unsigned 64-bit integer.

The urilen keyword does not require a content match on the http.uri buffer or the http.uri.raw buffer.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request"; flow:established,to_server; urilen:11; http.method; content:"GET"; classtype:bad-unknown; sid:40; rev:1;)

The above signature would match on any HTTP GET request that has a URI length of 11, regardless of the content or structure of the URI.

The following signatures would all alert on the example request above as well and show the different urilen options.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen greater than 10"; flow:established,to_server; urilen:>10; classtype:bad-unknown; sid:41; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen less than 12"; flow:established,to_server; urilen:<12; classtype:bad-unknown; sid:42; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen greater/less than example"; flow:established,to_server; urilen:10<>12; classtype:bad-unknown; sid:43; rev:1;)
8.13.18. http.location

The http.location keyword is used to match on the HTTP response location header contents.

It is possible to use any of the Payload Keywords with the http.location keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54
Location: suricata.io

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Location Example"; flow:established,to_client; http.location; content:"suricata.io"; bsize:11; classtype:bad-unknown; sid:122; rev:1;)

Note

http.location does not include the leading space or trailing \r\n

Note

http.location can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.19. http.response_body

The http.response_body keyword is used to match on the HTTP response body.

It is possible to use any of the Payload Keywords with the http.response_body keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

Server response body

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Response Body Example"; flow:established,to_client; http.response_body; content:"Server response body"; classtype:bad-unknown; sid:120; rev:1;)

Note

http.response_body will match on gzip decoded data just like file.data does.

Note

How much of the response/server body is inspected is controlled in your libhtp configuration section via the response-body-limit setting.

Note

http.response_body replaces the previous keyword name, http_server_body. http_server_body can still be used but it is recommended that rules be converted to use http.response_body.
8.13.20. http.response_header

The http.response_header keyword is used to match on the name and value of an HTTP/1 or HTTP/2 request.

It is possible to use any of the Payload Keywords with the http.response_header keyword.

For HTTP/2, the header name and value get concatenated by ": " (colon and space). The colon and space are commonly noted with the hexadecimal format |3a 20| within signatures.

To detect if an HTTP/2 header name contains a ":" (colon), the keyword http2.header_name can be used.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54
Location: suricata.io

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Response Example"; flow:established,to_client; http.response_header; content:"Location|3a 20|suricata.io"; classtype:bad-unknown; sid:127; rev:1;)
8.13.21. http.response_line

The http.response_line keyword is used to match on the entire HTTP response line.

It is possible to use any of the Payload Keywords with the http.response_line keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Response Line Example"; flow:established,to_client; http.response_line; content:"HTTP/1.1 200 OK"; classtype:bad-unknown; sid:119; rev:1;)

Note

http.response_line does not include the trailing \r\n
8.13.22. http.server

The http.server keyword is used to match on the HTTP response server header contents.

It is possible to use any of the Payload Keywords with the http.server keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Server Example"; flow:established,to_client; http.server; content:"nginx/0.8.54"; bsize:12; classtype:bad-unknown; sid:121; rev:1;)

Note

http.server does not include the leading space or trailing \r\n

Note

http.server can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.23. http.stat_code

The http.stat_code keyword is used to match on the HTTP status code that can be present in an HTTP response.

It is possible to use any of the Payload Keywords with the http.stat_code keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Code Response Example"; flow:established,to_client; http.stat_code; content:"200"; classtype:bad-unknown; sid:117; rev:1;)

Note

http.stat_code does not include the leading or trailing space
8.13.24. http.stat_msg

The http.stat_msg keyword is used to match on the HTTP status message that can be present in an HTTP response.

It is possible to use any of the Payload Keywords with the http.stat_msg keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Message Response Example"; flow:established,to_client; http.stat_msg; content:"OK"; classtype:bad-unknown; sid:118; rev:1;)

Note

http.stat_msg does not include the leading space or trailing \r\n

Note

http.stat_msg will always be empty when used with HTTP/2
8.13.25. file.data

With file.data, the HTTP response body is inspected, just like with http.response_body. file.data also works for HTTP request body and can be used in protocols other than HTTP.

It is possible to use any of the Payload Keywords with the file.data keyword.

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

Server response body

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP file.data Example"; flow:established,to_client; file.data; content:"Server response body"; classtype:bad-unknown; sid:128; rev:1;)

The body of an HTTP response can be very large, therefore the response body is inspected in definable chunks.

How much of the response/server body is inspected is controlled in the libhtp configuration section via the response-body-limit setting.

Note

If the HTTP body is a flash file compressed with 'deflate' or 'lzma', it can be decompressed and file.data can match on the decompressed data. Flash decompression must be enabled under 'libhtp' configuration:

# Decompress SWF files.
# 2 types: 'deflate', 'lzma', 'both' will decompress deflate and lzma
# compress-depth:
# Specifies the maximum amount of data to decompress,
# set 0 for unlimited.
# decompress-depth:
# Specifies the maximum amount of decompressed data to obtain,
# set 0 for unlimited.
swf-decompression:
  enabled: yes
  type: both
  compress-depth: 0
  decompress-depth: 0

Note

file.data replaces the previous keyword name, file_data. file_data can still be used but it is recommended that rules be converted to use file.data.

Note

If an HTTP body is using gzip or deflate, file.data will match on the decompressed data.

Note

Negated matching is affected by the chunked inspection. E.g. 'content:!"<html";' could not match on the first chunk, but would then possibly match on the 2nd. To avoid this, use a depth setting. The depth setting takes the body size into account. Assuming that the response-body-minimal-inspect-size is bigger than 1k, 'content:!"<html"; depth:1024;' can only match if the pattern '<html' is absent from the first inspected chunk.

Note

Additional information can be found at File Keywords

Note

file.data supports multiple buffer matching, see Multiple Buffer Matching.
8.13.26. http.connection

The http.connection keyword is used to match on the Connection field that can be present in HTTP request or response headers.

It is possible to use any of the Payload Keywords with the http.connection keyword.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Accept-Language: en-US
Host: suricata.io
Connection: Keep-Alive

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Connection Example"; flow:established,to_server; http.connection; content:"Keep-Alive"; bsize:10; classtype:bad-unknown; sid:94; rev:1;)

Note

http.connection does not include the leading space or trailing \r\n

Note

http.connection can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.27. http.content_len

The http.content_len keyword is used to match on the Content-Length field that can be present in HTTP request or response headers. Use flow:to_server or flow:to_client to force inspection of the request or response respectively.

It is possible to use any of the Payload Keywords with the http.content_len keyword.

Example HTTP Request:

POST /suricata.php HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------123
Host: suricata.io
Content-Length: 100
Connection: Keep-Alive

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54
Connection: Close
Content-Length: 20

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Length Request Example"; flow:established,to_server; http.content_len; content:"100"; bsize:3; classtype:bad-unknown; sid:97; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Content-Length Response Example"; flow:established,to_client; http.content_len; content:"20"; bsize:2; classtype:bad-unknown; sid:98; rev:1;)

To do numeric evaluation of the content length, byte_test can be used.

If we want to match on an HTTP request content length equal to and greater than 100 we could use the following signature.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Length Request Byte Test Example"; flow:established,to_server; http.content_len; byte_test:0,>=,100,0,string,dec; classtype:bad-unknown; sid:99; rev:1;)

Note

http.content_len does not include the leading space or trailing \r\n
8.13.28. http.content_type

The http.content_type keyword is used to match on the Content-Type field that can be present in HTTP request or response headers. Use flow:to_server or flow:to_client to force inspection of the request or response respectively.

It is possible to use any of the Payload Keywords with the http.content_type keyword.

Example HTTP Request:

POST /suricata.php HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------123
Host: suricata.io
Content-Length: 100
Connection: Keep-Alive

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54
Connection: Close

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Type Request Example"; flow:established,to_server; http.content_type; content:"multipart/form-data|3b 20|"; startswith; classtype:bad-unknown; sid:95; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Content-Type Response Example"; flow:established,to_client; http.content_type; content:"text/html"; bsize:9; classtype:bad-unknown; sid:96; rev:1;)

Note

http.content_type does not include the leading space or trailing \r\n

Note

http.content_type can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.29. http.cookie

The http.cookie keyword is used to match on the cookie field that can be present in HTTP request (Cookie) or HTTP response (Set-Cookie) headers.

It is possible to use any of the Payload Keywords with both http.header keywords.

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Cookie: PHPSESSION=123
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Cookie Example"; flow:established,to_server; http.cookie; content:"PHPSESSIONID=123"; bsize:14; classtype:bad-unknown; sid:80; rev:1;)

Note

Cookies are passed in HTTP headers but Suricata extracts the cookie data to http.cookie and will not match cookie content put in the http.header sticky buffer.

Note

http.cookie does not include the leading space or trailing \r\n

Note

http.cookie can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.30. http.header

Matching on HTTP headers has two options in Suricata, the http.header and the http.header.raw.

It is possible to use any of the Payload Keywords with both http.header keywords.

The http.header keyword normalizes the header contents. For example if header contents contain trailing white-space or tab characters, those would be removed.

To match on non-normalized header data, use the http.header.raw keyword.

Normalization Example:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0     \r\n
Host: suricata.io

Would be normalized to Mozilla/5.0\r\n

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 1"; flow:established,to_server; http.header; content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|"; classtype:bad-unknown; sid:70; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 2"; flow:established,to_server; http.header; content:"Host|3a 20|suricata.io|0d 0a|"; classtype:bad-unknown; sid:71; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 3"; flow:established,to_server; http.header; content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|"; startswith; content:"Host|3a 20|suricata.io|0d 0a|"; classtype:bad-unknown; sid:72; rev:1;)

Note

There are headers that will not be included in the http.header buffer, specifically the http.cookie buffer.

Note

http.header can have additional formatting/normalization applied to buffer contents, see Normalization for additional details.
8.13.31. http.header.raw

The http.header.raw buffer matches on HTTP header content but does not have any normalization performed on the buffer contents (see http.header)

Abnormal HTTP Header Example:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
User-Agent: Chrome
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Raw Example"; flow:established,to_server; http.header.raw; content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|"; content:"User-Agent|3a 20|Chrome|0d 0a|"; classtype:bad-unknown; sid:73; rev:1;)

Note

http.header.raw can have additional formatting applied to buffer contents, see Normalization for additional details.
8.13.32. http.header_names

The http.header_names keyword is used to match on the names of the headers in an HTTP request or response. This is useful for checking for a header's presence, absence and/or header order. Use flow:to_server or flow:to_client to force inspection of the request or response respectively.

It is possible to use any of the Payload Keywords with the http.header_names keyword.

Example HTTP Request:

GET / HTTP/1.1
Host: suricata.io
Connection: Keep-Alive

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

Examples to match exactly on header order:

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request Example"; flow:established,to_server; http.header_names; content:"|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; bsize:22; classtype:bad-unknown; sid:110; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response Example"; flow:established,to_client; http.header_names; content:"|0d 0a|Content-Type|0d 0a|Server|0d 0a 0d a0|"; bsize:26; classtype:bad-unknown; sid:111; rev:1;)

Examples to match on header existence:

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request Example 2"; flow:established,to_server; http.header_names; content:"|0d 0a|Host|0d 0a|"; classtype:bad-unknown; sid:112; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response Example 2"; flow:established,to_client; http.header_names; content:"|0d 0a|Content-Type|0d 0a|"; classtype:bad-unknown; sid:113; rev:1;)

Examples to match on header absence:

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request Example 3"; flow:established,to_server; http.header_names; content:!"|0d 0a|User-Agent|0d 0a|"; classtype:bad-unknown; sid:114; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response Example 3"; flow:established,to_client; http.header_names; content:!"|0d 0a|Date|0d 0a|"; classtype:bad-unknown; sid:115; rev:1;)

Example to check for the User-Agent header and that the Host header is after User-Agent but not necessarily directly after.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request Example 4"; flow:established,to_server; http.header_names; content:"|0d 0a|Host|0d 0a|"; content:"User-Agent|0d 0a|"; distance:-2; classtype:bad-unknown; sid:114; rev:1;)

Note

http.header_names starts with a \r\n and ends with an extra \r\n.
8.13.33. http.protocol

The http.protocol keyword is used to match on the protocol field that is contained in HTTP requests and responses.

It is possible to use any of the Payload Keywords with the http.protocol keyword.

Note

http.protocol does not include the leading space or trailing \r\n

Example HTTP Request:

GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0
Host: suricata.io

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Protocol Example"; flow:established,to_server; http.protocol; content:"HTTP/1.1"; bsize:9; classtype:bad-unknown; sid:50; rev:1;)
8.13.34. http.start

The http.start keyword is used to match on the start of an HTTP request or response. This will contain the request/response line plus the request/response headers. Use flow:to_server or flow:to_client to force inspection of the request or response respectively.

It is possible to use any of the Payload Keywords with the http.start keyword.

Example HTTP Request:

GET / HTTP/1.1
Host: suricata.io
Connection: Keep-Alive

Example HTTP Response:

HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/0.8.54

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Start Request Example"; flow:established,to_server; http.start; content:"POST / HTTP/1.1|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; classtype:bad-unknown; sid:101; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Start Response Example"; flow:established,to_client; http.start; content:"HTTP/1.1 200 OK|0d 0a|Content-Type|0d 0a|Server|0d 0a 0d a0|"; classtype:bad-unknown; sid:102; rev:1;)

Note

http.start contains the normalized headers and is terminated by an extra \r\n to indicate the end of the headers.

# CSC361
UVic Networking course assignments

# How to use
python3 SmartClient.py <domain name>

## Examples of domain name input format
www.uvic.ca
uvic.ca

# HTTP response code handling and SmartClient output
2xx codes - sucessful connection; supports HTTP version; SmartClient will output 'Yes'
3xx codes - successful connection; supports HTTP version; SmartClient will output 'Yes'
4xx codes - Client error; inconclusive on HTTP version support; SmartClient will output 'No, <response code>' for HTTP1.1 and HTTPs tests
5xx codes - Server error; inconclusive on HTTP version support; SmartClient will output 'No, <response code>' for HTTP1.1 and HTTPs tests
505 code  - Server does not support the HTTP version; SmartClient will output 'No, <response code>' for HTTP1.1 and HTTPs tests

# Example output
Each test will output the request message and the response body.
Ends with the expected summary output

```
----Testing HTTP2 Support---
----Request begin----
GET / HTTP/2
Host: www.uvic.ca
Connection: Keep-alive


----Request end-----
HTTP request sent, awaiting response...


----Response output----
SELECTED PROTOCOL: None
HTTP/1.0 302 Found
...


----Testing HTTPs Support---
----Request begin---
GET / HTTP/1.1
Host: www.uvic.ca
Connection: Keep-alive


----Request end-----
HTTPs request sent, awaiting response...


----Response output----
HTTP/1.1 200 OK
Date: Sat, 30 Jan 2021 06:35:11 GMT
...
        
----Testing HTTP1.1 Support---
----Request begin---
GET / HTTP/1.1
Host: www.uvic.ca
Connection: Keep-alive


----Request end-----
HTTP request sent, awaiting response...


----Response output----
HTTP/1.0 302 Found
Location: https://www.uvic.ca/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0


website: www.uvic.ca
1. Supports of HTTPs: Yes
2. Supports of http1.1: Yes
3. Supports of http2: No
4: List of Cookies: 
cookie name:   PHPSESSID, 
cookie name:   uvic_bar, expires time:  Thu, 01-Jan-1970 00:00:01 GMT, domain name:  .uvic.ca
cookie name:   www_def, 
cookie name:   TS0168706e, domain name:  .www.uvic.ca
```
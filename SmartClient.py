import sys
import ssl
import time
import os
import select
import threading
from socket import *

TLS_PORT = 443
HTTP_PORT = 80
PORT = 443
BUFFER_SIZE = 2028
cookies_str = []

https_support= 'No'
http1_1_support = 'No'
http2_support = 'No'

def add_cookie_get_code(data):
    global cookies_str
    #Split data by lines and store in list
    data_list = data.split('\n')
    #Store response code
    code = data_list[0]
    for item in data_list:
        #Convert to lower case
        item = item.lower()
        #Find cookies
        if('set-cookie:' not in item):
            continue
        cookies_str.append(item)
    return code

def test_http2_support(domain):
    global http2_support, http1_1_support
    print("----HTTP2 SUPPORT ---")

    #Create SSL Context
    context = ssl.create_default_context()
    #Set ALPN protocols
    context.set_alpn_protocols(['h2', 'http/1.1'])
    #Create connection
    sock = socket(AF_INET, SOCK_STREAM)
    #Wrap connection with SSL
    conn = context.wrap_socket(sock, server_hostname=domain)
    #Open connection
    try:
        conn.connect((domain, TLS_PORT))
    except ssl.SSLError as e:
        print("Probably invalid domain entered or can't find in DNS listing.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("connected...")
    
    #Send HTTP request
    request = 'HEAD / HTTP/2\r\nHost: {}\r\n\r\n'.format(domain)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("requested...")

    #Get selected alpn protocol
    protocol = conn.selected_alpn_protocol()
    #Print selected protocol
    print("SELECTED PROTOCOL: " + repr(protocol).replace(' ', r'\s'))
 
    if(protocol == 'h2'):
        http2_support = 'Yes'
        http1_1_support = 'Yes'
    elif(protocol == 'http/1.1'):
        http1_1_support = 'Yes'
    
    #Get HTTP response 
    try:
        data = conn.recv(BUFFER_SIZE).decode() 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("recieved...")
        print(data)
        http2_support = http2_support + add_cookie_get_code(data)


    conn.close() #Close connection
    return False


def test_https_support(domain):
    global cookies_str
    global https_support
    print("----HTTPS SUPPORT ---", domain)
    #Create SSL Context
    context = ssl.create_default_context()
    #Create connection
    sock = socket(AF_INET, SOCK_STREAM)
    #Wrap connection with SSL
    conn = context.wrap_socket(sock, server_hostname=domain)
    #Open connection
    try:
        conn.connect((domain, TLS_PORT))
    except ssl.SSLError as e:
        print("Probably invalid domain entered or can't find in DNS listing.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("connected...")
    
    
    #Send HTTP request
    request = 'HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(domain)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("requested...")

    #Get HTTP response 
    try:
        data = conn.recv(BUFFER_SIZE).decode() 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("recieved...")
        print(data)
        https_support = add_cookie_get_code(data)
    
    conn.close() #Close connection
    return True

def test_http1_1_support(domain):
    global http1_1_support
    print("----HTTP1.1 SUPPORT ---")

    #Create connection
    conn = socket(AF_INET, SOCK_STREAM)
    #Open connection 
    try:
        conn.connect((domain, HTTP_PORT))
    except ssl.SSLError as e:
        print("Probably invalid domain entered or can't find in DNS listing.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("connected...")
    
    #Send HTTP request
    request = 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(domain)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("requested...")

    #Get HTTP response 
    try:
        data = conn.recv(BUFFER_SIZE).decode() 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print("recieved...")
        print(data)
        http1_1_support = add_cookie_get_code(data)
    
    
    conn.close() #Close connection
    return True

def main():
    #Read in input
    if(len(sys.argv) < 2):
        print("Missing domain name: python3 SmartClient.py <domain name>")
        sys.exit(2)
    domain_name = str(sys.argv[1])
    try:
        test_https_support(domain_name)
        test_http1_1_support(domain_name)
        test_http2_support(domain_name)
    except Exception as e:
        sys.exit(2)
    
    print("website: " + repr(domain_name).replace(' ', r'\s'))
    print("1. Supports of HTTPs: " + https_support)
    print("2. Supports of http1.1: " + http1_1_support) 
    print("3. Supports of http2: " + http2_support) 
    print("4: List of Cookies: \n", "\n".join(list(dict.fromkeys(cookies_str))))

if __name__ == "__main__":
    main()
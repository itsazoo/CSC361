import sys
import ssl
import time
import os
import select
import threading
import re
from socket import *

TLS_PORT = 443
HTTP_PORT = 80
PORT = 443
BUFFER_SIZE = 2028
cookies_list = []

https_support= 'No'
http1_1_support = 'No'
http2_support = 'No'

COOKIE_NAME = 'cookie name: '
EXPIRES_TIME = 'expires time: '
DOMAIN_NAME = 'domain name: '

def print_cookies(cookies_list):
    for cookie in cookies_list:
        if(COOKIE_NAME in cookie.keys()):
            print(COOKIE_NAME, cookie[COOKIE_NAME], end = ', ')
        if(EXPIRES_TIME in cookie.keys()):
            print(EXPIRES_TIME, cookie[EXPIRES_TIME], end = ', ')
        if(DOMAIN_NAME in cookie.keys()):
            print(DOMAIN_NAME, cookie[DOMAIN_NAME], end = '')
        print()
    
def parse_cookie(cookie):
    cookie_dict = {}
    cookie_data = cookie.split(';')
    for item in cookie_data:
        cookie_item = item.lower()
        if('set-cookie:' in cookie_item):
            stripped_cookie_key = item.split('=')
            cookie_name_list = stripped_cookie_key[0].split(':')
            cookie_name = cookie_name_list[1]
            cookie_dict[COOKIE_NAME] = cookie_name
        if('domain' in cookie_item):
            domain_name_list = item.split('=')
            domain_name = domain_name_list[1]
            cookie_dict[DOMAIN_NAME] = domain_name
        if('expires' in cookie_item):
            expire_time_list = item.split('=')
            expire_time = expire_time_list[1]
            cookie_dict[EXPIRES_TIME] = expire_time
    return cookie_dict

def add_cookie(data):
    global cookies_list

    #Split data by lines and store in list
    data_list = data.split('\n')
    for item in data_list:
        cookie_item = item.lower()
        #Find cookies
        if('set-cookie:' not in cookie_item):
            continue
        cookies_list.append(parse_cookie(item))

def get_code(data):
    data_list = data.split('\n')
    return str(data_list[0])

def format_result(result, code):
    verdict = result + ", " + code
    return verdict


def interpret_response_code(code):
    if(code == ""):
        return 'No'

    if(re.search(r'4\d\d', code)):
        return format_result('No', code)
    
    if(re.search(r'5\d\d', code)):
        return format_result('No', code)

    if('HTTP/1.0' in code):
        if('302' not in code):
            return format_result('No', code)

    return 'Yes'

def test_http2_support(domain, request):
    global http2_support, http1_1_support
    print("----Testing HTTP2 Support---")
    #Create SSL Context
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
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
        return
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        return
        
    
    #Send HTTP2 request
    print("----Request begin----")
    print(request)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        

    print("----Request end-----\nHTTP request sent, awaiting response...\n\n")
    #Get selected alpn protocol
    protocol = conn.selected_alpn_protocol()
    #Print selected protocol
    print("----Response output----")
    print("SELECTED PROTOCOL: " + repr(protocol).replace(' ', r'\s'))
 
    if(protocol == 'h2'):
        http2_support = 'Yes'
    elif(protocol == 'http/1.1'):
        http1_1_support = 'Yes'
    
    #Get HTTP2 response 
    try:
        data = conn.recv(BUFFER_SIZE).decode(errors='ignore') 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
    else:
        print(data)
        add_cookie(data)


    conn.close() #Close connection


def test_https_support(domain, request):
    print("----Testing HTTPs Support---")
    global cookies_list
    global https_support, http1_1_support
    #Create SSL Context
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    #Create connection
    sock = socket(AF_INET, SOCK_STREAM)
    #Wrap connection with SSL
    conn = context.wrap_socket(sock, server_hostname=domain)
    #Open connection
    try:
        conn.connect((domain, TLS_PORT))
    except ssl.SSLError as e:
        print("Probably invalid domain entered or can't find in DNS listing.")
        return
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        return
        
    
    
    #Send HTTPs request
    print("----Request begin---")
    print(request)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        

    print("----Request end-----\nHTTPs request sent, awaiting response...\n\n")

    #Get HTTP response 
    print("----Response output----")
    try:
        data = conn.recv(BUFFER_SIZE).decode(errors='ignore') 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        
    else:
        print(data)
        add_cookie(data)
        response_code = get_code(data)
        https_support = interpret_response_code(response_code)
        http1_1_support = interpret_response_code(response_code)
    
    conn.close() #Close connection

def test_http1_1_support(domain, request):
    global http1_1_support

    print("----Testing HTTP1.1 Support---")
    #Create connection
    conn = socket(AF_INET, SOCK_STREAM)
    #Open connection 
    try:
        conn.connect((domain, HTTP_PORT))
    except ssl.SSLError as e:
        print("Probably invalid domain entered or can't find in DNS listing.")
        return
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        return
        
    

    #Send HTTP request
    print("----Request begin---")
    print(request)
    try: 
        conn.send(request.encode())
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        
    
    print("----Request end-----\nHTTP request sent, awaiting response...\n\n")

    #Get HTTP response 
    print("----Response output----")
    try:
        data = conn.recv(BUFFER_SIZE).decode(errors='ignore') 
    except UnicodeDecodeError:
        print("Cannot decode message.")
    except Exception as e:
        print("Unexpected Error Occured: {}".format(e))
        
    else:
        print(data)
        add_cookie(data)
        response_code = get_code(data)
        http1_1_support = interpret_response_code(response_code)
    
    conn.close() #Close connection

def main():
    #Read in input
    if(len(sys.argv) < 2):
        print("Missing domain name: python3 SmartClient.py <domain name>")
        sys.exit(2)
    domain_name = str(sys.argv[1])
    try:
        test_http2_support(domain_name, 'GET / HTTP/2\r\nHost: {}\r\nConnection: Keep-alive\r\n\r\n'.format(domain_name))
        test_https_support(domain_name, 'GET / HTTP/1.1\r\nHost: {}\r\nConnection: Keep-alive\r\n\r\n'.format(domain_name))
        test_http1_1_support(domain_name, 'GET / HTTP/1.1\r\nHost: {}\r\nConnection: Keep-alive\r\n\r\n'.format(domain_name))
    except Exception as e:
        print(e)
    else:
        print("\n\n\n\n\n\n\nwebsite: {}".format(domain_name))
        print("1. Supports of HTTPs: {}".format(https_support))
        print("2. Supports of http1.1: {}".format(http1_1_support)) 
        print("3. Supports of http2: {}".format(http2_support)) 
        print("4: List of Cookies: ")
        print_cookies(cookies_list)

if __name__ == "__main__":
    main()
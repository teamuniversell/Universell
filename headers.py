from urllib.request import Request, urlopen, FancyURLopener
import re
import time

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
	# This function will print(the server headers such as WebServer OS & Version.
	print(ga.bold+" \n [!] Fingerprinting the backend Technologies."+ga.end)
 
	req = Request(url)
	req.add_header("User-Agent","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0")
	opener = urlopen(req)
 
	if opener.getcode() == 200:
		print(ga.green+" [!] Status code: 200 OK"+ga.end)
	if opener.getcode() == 404:
		print(ga.red+" [!] Page was not found! Please check the URL \n"+ga.end)
		exit()
	
	Server = opener.headers.get(HTTP_HEADER.SERVER)
	
	Host = url.split("/")[2]
	print(ga.green+" [!] Host: " + str(Host) +ga.end)
	print(ga.green+" [!] WebServer: " + str(Server) +ga.end)


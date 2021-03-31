from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from ipaddress import ip_address, IPv6Address
from socket import IPPROTO_TCP
import sys
import matplotlib.pyplot as plt

class Flow(object):
    def __init__(self, data):
        self.pkts = 0
        self.flows = 0
        self.ft = {}
        for pkt, metadata in RawPcapReader(data):
            self.pkts += 1
            ether = Ether(pkt)
            if ether.type == 0x86dd:
                ip = ether[IPv6]
                if ip.nh != 6:
                    continue
                else:
                    flow_size = ip.plen
            elif ether.type == 0x0800:
                ip = ether[IP]
                if ip.proto != 6:
                    continue
                else:
                    flow_size = ip.len - ip.ihl * 4
            tcp = ip[TCP]
            key = (int(ip_address(ip.src)), int(ip_address(ip.dst)), tcp.sport, tcp.dport)
            reverse_key = (int(ip_address(ip.dst)), int(ip_address(ip.src)), tcp.dport, tcp.sport)
            if self.ft.__contains__(key):
                self.ft[key] = flow_size + self.ft[key]
            elif self.ft.__contains__(reverse_key):
                self.ft[reverse_key] = flow_size + self.ft[reverse_key]
            else:
                self.ft[key] = flow_size
    def Plot(self):
        topn = 100
        data = [i/1000 for i in list(self.ft.values())]
        data.sort()
        data = data[-topn:]
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.hist(data, bins=20, log=True)
        ax.set_ylabel('# of flows')
        ax.set_xlabel('Data sent [KB]')
        ax.set_title('Top {} TCP flow size distribution.'.format(topn))
        plt.savefig(sys.argv[1] + '.flows.pdf', bbox_inches='tight')
        plt.close()

if __name__ == '__main__':
    d = Flow(sys.argv[1])
    d.Plot()

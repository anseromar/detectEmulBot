from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff


class HttpPacket:
    def __init__(self, macdest, macori, header):
        self.ori = macori
        self.dst = macdest
        tab = filter(None, header.split("\\r\\n"))
        body = False
        self.headers = []
        self.body = []
        for h in tab:
            if body:
                self.body.append(h)
            else:
                self.headers.append(h)
                if str(h).startswith('Content-Length'):
                    body = True

    def __repr__(self):
        return "Http " + self.ori + " => " + self.dst + " { " + self.headers.__str__() + " }, {" + self.body.__str__() + "}"

    def __str__(self):
        return "Http " + self.ori + " => " + self.dst + " { " + self.headers.__str__() + " }, {" + self.body.__str__() + "}"


def pkt_callback(pkt):
    pkt.show()


def stopfilter(pkt):
    ret = False
    if TCP in pkt:
        http = HttpPacket(pkt[0][Ether].dst, pkt[0][Ether].src, str(pkt[0][TCP].payload))
        data = None
        packetData = None
        for header in http.headers:
            if header.lower().startswith('authorization'):
                data = header
                packetData = http
                ret = True
    return ret


# sniff(iface="wlo1", prn=pkt_callback, filter="tcp", store=0)
def main():
    # sniff(iface="wlo1", prn=pkt_callback, filter="tcp", store=0)
    sniff(iface="wlo1", filter='tcp',  prn=pkt_callback)


if __name__ == '__main__':
    main()

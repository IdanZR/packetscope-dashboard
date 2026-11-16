"""Generate clearly synthetic documentation-range traffic; does not send packets."""
from pathlib import Path
from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap, PcapNgWriter


def demo_packets():
    client = "192.0.2.10"
    server = "198.51.100.20"
    eth = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
    packets = [
        eth/ARP(psrc=client, pdst="192.0.2.1"),
        eth/IP(src=client,dst="192.0.2.53")/UDP(sport=53000,dport=53)/DNS(id=10,qd=DNSQR(qname="example.test")),
        eth/IP(src="192.0.2.53",dst=client)/UDP(sport=53,dport=53000)/DNS(id=10,qr=1,qd=DNSQR(qname="example.test"),an=DNSRR(rrname="example.test",rdata=server)),
        eth/IP(src=client,dst=server)/TCP(sport=50000,dport=80,flags="S"),
        eth/IP(src=server,dst=client)/TCP(sport=80,dport=50000,flags="SA"),
        eth/IP(src=client,dst=server)/TCP(sport=50000,dport=80,flags="PA")/Raw(b"GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        eth/IP(src=server,dst=client)/TCP(sport=80,dport=50000,flags="PA")/Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDemo"),
        eth/IP(src=client,dst=server)/TCP(sport=50001,dport=443,flags="PA")/Raw(b"\x17\x03\x03\x00\x04demo"),
        eth/IP(src=client,dst=server)/ICMP(),
        eth/IPv6(src="2001:db8::10",dst="2001:db8::20")/UDP(sport=51000,dport=9000)/Raw(b"Synthetic IPv6 demo"),
    ]
    # Real TCP sequence/acknowledgement numbers make the HTTP pair independently verifiable.
    packets[3][TCP].seq = 1000
    packets[4][TCP].seq, packets[4][TCP].ack = 2000, 1001
    packets[5][TCP].seq, packets[5][TCP].ack = 1001, 2001
    packets[6][TCP].seq, packets[6][TCP].ack = 2001, 1001 + len(bytes(packets[5][TCP].payload))
    for i, packet in enumerate(packets):
        packet.time = 1_800_000_000 + i
    return packets


def http_demo_packets():
    """One persistent connection: three pairs and a request with no response."""
    packets = []
    sequence = [1000, 9000]
    def send(side, payload):
        packet = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
        packet /= IP(src="192.0.2.10" if side == 0 else "198.51.100.20",
                     dst="198.51.100.20" if side == 0 else "192.0.2.10")
        packet /= TCP(sport=51000 if side == 0 else 80, dport=80 if side == 0 else 51000,
                      seq=sequence[side], ack=sequence[1-side], flags="PA")/Raw(payload)
        packet.time = 1_800_000_000 + len(packets) * .25
        sequence[side] += len(payload)
        packets.append(packet)
    send(0, b"GET /home HTTP/1.1\r\nHost: example.test\r\nUser-Agent: PacketScope sample\r\n\r\n")
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nWelcome"
    send(1, response[:24])
    send(1, response[24:])
    send(0, b"GET /missing HTTP/1.1\r\nHost: example.test\r\n\r\n")
    send(1, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    send(0, b"POST /form HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\n\r\nname=A")
    send(1, b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n5\r\nSaved\r\n0\r\n\r\n")
    send(0, b"GET /pending HTTP/1.1\r\nHost: example.test\r\n\r\n")
    return packets


def generate(directory=None):
    target = Path(directory) if directory else Path(__file__).parent / "sample_data"
    target.mkdir(parents=True, exist_ok=True)
    packets = demo_packets()
    wrpcap(str(target / "demo.pcap"), packets)
    with PcapNgWriter(str(target / "demo.pcapng")) as writer:
        for packet in packets:
            writer.write(packet)
    http_packets = http_demo_packets()
    wrpcap(str(target / "http_transactions.pcap"), http_packets)
    with PcapNgWriter(str(target / "http_transactions.pcapng")) as writer:
        for packet in http_packets:
            writer.write(packet)
    return target


if __name__ == "__main__":
    print(f"Created synthetic PCAP and PCAPNG in {generate()}")

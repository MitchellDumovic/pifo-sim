from scapy.all import *

pkts = []

def generate_packet(ip_src_idx, ip_dst_idx, tcp_src_idx, tcp_dst_idx, payload_len):
  TCP_PKT = Ether() / IP(dst = IP_DSTS[ip_dst_idx], src = IP_SRCS[ip_src_idx]) / \
          TCP(sport = TCP_SRCS[tcp_src_idx], dport = TCP_DSTS[tcp_dst_idx]) / os.urandom(payload_len)
  return TCP_PKT

IP_SRCS = ['10.10.10.10', "20.20.20.20", "30.30.30.30", "40.40.40.40"]
IP_DSTS = ['11.11.11.11', "21.21.21.21", "31.31.31.31", "41.41.41.41"]
TCP_SRCS = [10, 20, 30, 40]
TCP_DSTS = [11, 21, 31, 41]

ROUNDS = 2 ** 8
FLOW_1_MULT = 1
FLOW_2_MULT = 2
FLOW_3_MULT = 3
FLOW_4_MULT = 4

# BASELINE TESTS #

# 1. Test fair queueing behavior
def test_1():
    for i in range(ROUNDS):
      for j in range(FLOW_1_MULT):
        pkts.append(generate_packet(0, 0, 0, 0, 20))
      for j in range(FLOW_2_MULT):
        pkts.append(generate_packet(1, 1, 1, 1, 20))
      for j in range(FLOW_3_MULT):
        pkts.append(generate_packet(2, 2, 2, 2, 20))
      for j in range(FLOW_4_MULT):
        pkts.append(generate_packet(3, 3, 3, 3, 20))

# 2. Test virtual time approximation accuracy
def test_2():
    for i in range(ROUNDS):
      for j in range(FLOW_1_MULT):
        if i in (list(range(100)) + list(range(200, 300))):
          pkts.append(generate_packet(0, 0, 0, 0, 20))
      for j in range(FLOW_2_MULT):
        pkts.append(generate_packet(1, 1, 1, 1, 20))
      for j in range(FLOW_3_MULT):
        pkts.append(generate_packet(2, 2, 2, 2, 20))
      for j in range(FLOW_4_MULT):
        pkts.append(generate_packet(3, 3, 3, 3, 20))
    for i in range(4 * ROUNDS):
      pkts.append(generate_packet(0, 0, 0, 0, 20))

test_1()
wrpcap('src.pcap', pkts)

f = open('ranks.txt','w')
for i in range(len(pkts)):
    f.write('0\n')
f.close()

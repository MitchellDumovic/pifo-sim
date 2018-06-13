from scapy.all import *

def generate_packet(ip_src_idx, ip_dst_idx, tcp_src_idx, tcp_dst, payload_idx):
  TCP_PKT = Ether() / IP(dst = IP_DSTS[ip_dst_idx], src = IP_SRCS[ip_src_idx]) / \
          TCP(sport = TCP_SRCS[tcp_src_idx], dport = tcp_dst) / os.urandom(PAYLOAD_SIZES[payload_idx])
  return TCP_PKT

IP_SRCS = ['10.10.10.10', "20.20.20.20", "30.30.30.30", "40.40.40.40", "50.50.50.50", "60.60.60.60"]
IP_DSTS = ['11.11.11.11', "21.21.21.21", "31.31.31.31", "41.41.41.41"]
TCP_SRCS = [10, 20, 30, 40, 45, 50, 55]
PAYLOAD_SIZES = [20, 40, 80, 160, 320]

ROUNDS = 2 ** 8
FLOW_1_MULT = 1
FLOW_2_MULT = 2
FLOW_3_MULT = 3
FLOW_4_MULT = 4

# BASELINE TESTS #

# 1. Test fair queueing behavior
def test_1():
  print "TEST 1"
  pkts = []
  for i in range(ROUNDS):
    for j in range(FLOW_1_MULT):
      pkts.append(generate_packet(0, 0, 0, 0, 0))
    for j in range(FLOW_2_MULT):
      pkts.append(generate_packet(1, 1, 1, 1, 0))
    for j in range(FLOW_3_MULT):
      pkts.append(generate_packet(2, 2, 2, 2, 0))
    for j in range(FLOW_4_MULT):
      pkts.append(generate_packet(3, 3, 3, 3, 0))
  print "DONE"
  return pkts

# 2. Test virtual time approximation accuracy
def test_2():
  print "TEST 2"
  pkts = []
  for i in range(ROUNDS):
    for j in range(FLOW_1_MULT):
      if i in (list(range(40)) + list(range(200, 300))):
        pkts.append(generate_packet(0, 0, 0, 0, 0))
    for j in range(FLOW_2_MULT):
      pkts.append(generate_packet(1, 1, 1, 1, 0))
    for j in range(FLOW_3_MULT):
      pkts.append(generate_packet(2, 2, 2, 2, 0))
    for j in range(FLOW_4_MULT):
      pkts.append(generate_packet(3, 3, 3, 3, 0))
  print "DONE"
  return pkts


# 16 flows 
def test_3():
  print "TEST 3"
  pkts = []
  for i in range(ROUNDS):
    for j in range(16):
      pkts.append(generate_packet(0, 0, 0, j+1, 0))
  print "DONE"
  return pkts

def test_4():
  print "TEST 4"
  pkts = []
  NUM_FLOWS = 50
  
  for i in range(2 ** 9):
    for j in range(NUM_FLOWS):
      pkt = generate_packet(j % len(IP_SRCS), j % len(IP_DSTS), j % len(TCP_SRCS), j, j % len(PAYLOAD_SIZES))
      pkts.append(pkt)
  print "DONE"
  return pkts


def test_5():
  print "TEST 5"
  pkts = []
  NUM_FLOWS = 50
  
  for i in range(2 ** 10):
    for j in range(NUM_FLOWS):
      
      if j % len(PAYLOAD_SIZES) == 4 and i in list(range(0, 2**9)):
        continue
      pkt = generate_packet(j % len(IP_SRCS), j % len(IP_DSTS), j % len(TCP_SRCS), j, j % len(PAYLOAD_SIZES))
      pkts.append(pkt)
  print "DONE"
  return pkts

def test_6():
  print "TEST 6"
  pkts = []
  NUM_FLOWS = 50
  
  for i in range(2 ** 10):
    for j in range(NUM_FLOWS):
      
      if j % len(PAYLOAD_SIZES) == 4 and i in list(range(0, 2**4)):
        pkt = generate_packet(j % len(IP_SRCS), j % len(IP_DSTS), j % len(TCP_SRCS), j, j % len(PAYLOAD_SIZES))
        pkts.append(pkt)
      pkt = generate_packet(j % len(IP_SRCS), j % len(IP_DSTS), j % len(TCP_SRCS), j, j % len(PAYLOAD_SIZES))
      pkts.append(pkt)
  print "DONE"
  return pkts



TESTS = [test_1, test_2, test_3, test_4]

for i, test in enumerate(TESTS):
  wrpcap('src-test-' + str(i + 1) + ".pcap", test())

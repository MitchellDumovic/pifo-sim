import crcmod
from scapy.all import *

HASH_POLYS = [0x104c11db7, 0x11edc6f41, 0x1814141AB, 0x1741B8CD7, 0x142F0E1EBA9EA3693]

CMS_width = 10


def get_hash_idxs(pkt):
        hash_fns = [crcmod.Crc(poly, initCrc = 0) for poly in HASH_POLYS]
        hashTuple = pkt[IP].src + pkt[IP].dst + str(pkt[IP].proto) + str(pkt.sport) + str(pkt.dport)

        for fn in hash_fns:
            fn.update(hashTuple)

        return [int(fn.hexdigest(), 16) % CMS_width for fn in hash_fns]

try:
    pkts = rdpcap('./test_data/src-test-4.pcap')
    pkts = filter(lambda pkt : UDP in pkt or TCP in pkt, pkts)
except IOError as e:
    print >> sys.stderr, "ERROR: failed to read pcap file: {}".format('./test_data/src.pcap')
    sys.exit(1)


hashindices = {}
for pkt in pkts[:20]:
    hashindices[pkt[IP].dport] = get_hash_idxs(pkt)

print hashindices

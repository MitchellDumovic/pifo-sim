
import sys, os
from scapy.all import *
import simpy
import crcmod
from utils.hwsim_tools import *

HASH_POLYS = [0x104c11db7, 0x11edc6f41, 0x11021]

class STFQCMSPipe(HW_sim_object):
    def __init__(self, env, period, r_in_pipe, r_out_pipe, w_in_pipe, w_out_pipe, CMS_width, vt_tracker):
        """
        r_in_pipe  : used to receive read result ACK
        r_out_pipe : used to return read result
        w_in_pipe  : used to receive write data
        w_out_pipe : used to indicate write completion
        """
        super(STFQCMSPipe, self).__init__(env, period)

        # Top level interface
        self.r_in_pipe = r_in_pipe
        self.r_out_pipe = r_out_pipe
        self.w_in_pipe = w_in_pipe
        self.w_out_pipe = w_out_pipe

        self.hash1_cms = [0 for i in range(CMS_width)]
        self.hash2_cms = [0 for i in range(CMS_width)]
        self.hash3_cms = [0 for i in range(CMS_width)]
        self.CMS_width = CMS_width

        self.vt_tracker = vt_tracker

        # register processes for simulation
        self.run()

    def run(self):
        self.env.process(self.compute_rank())

    def compute_rank(self):
        """
        Pipeline to compute rank for pkt
        """
        while not self.sim_done:
            # wait to receive incoming pkt
            (q_id, pkt) = yield self.w_in_pipe.get()
            self.w_out_pipe.put(1)

            hash1_idx, hash2_idx, hash3_idx = self.get_hash_idxs(pkt)
            penalty = self.get_penalty(hash1_idx, hash2_idx, hash3_idx)
            virtual_time = self.vt_tracker.virtual_time
            rank = max(virtual_time, penalty)
            self.set_penalty(rank, pkt, hash1_idx, hash2_idx, hash3_idx)

            self.r_out_pipe.put((rank, q_id, pkt))
            yield self.r_in_pipe.get()

    def update_hashes(self, hash_fns, val):
        for fn in hash_fns:
            fn.update(val)

    def get_hash_idxs(self, pkt):
        hash_fns = [crcmod.Crc(poly, initCrc = 0) for poly in HASH_POLYS]
        hashTuple = 0

        self.update_hashes(hash_fns, pkt[IP].src)
        self.update_hashes(hash_fns, pkt[IP].dst)
        self.update_hashes(hash_fns, str(pkt[IP].proto))

        if (TCP in pkt):
            self.update_hashes(hash_fns, str(pkt[TCP].sport))
            self.update_hashes(hash_fns, str(pkt[TCP].dport))
        elif (UDP in pkt):
            self.update_hashes(hash_fns, str(pkt[UDP].sport))
            self.update_hashes(hash_fns, str(pkt[UDP].dport))

        hash1_idx = int(hash_fns[0].hexdigest(), 16) % self.CMS_width
        hash2_idx = int(hash_fns[1].hexdigest(), 16) % self.CMS_width
        hash3_idx = int(hash_fns[2].hexdigest(), 16) % self.CMS_width

        return (hash1_idx, hash2_idx, hash3_idx)

    def get_penalty(self, hash1_idx, hash2_idx, hash3_idx):
        hash1_penalty = self.hash1_cms[hash1_idx]
        hash2_penalty = self.hash2_cms[hash2_idx]
        hash3_penalty = self.hash3_cms[hash3_idx]

        return min(hash1_penalty, hash2_penalty, hash3_penalty)

    def set_penalty(self, rank, pkt, hash1_idx, hash2_idx, hash3_idx):
        self.hash1_cms[hash1_idx] = rank + len(pkt)
        self.hash2_cms[hash2_idx] = rank + len(pkt)
        self.hash3_cms[hash3_idx] = rank + len(pkt)

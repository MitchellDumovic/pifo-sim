
import sys, os
from scapy.all import *
import simpy
from utils.hwsim_tools import *

class STFQPipe(HW_sim_object):
    def __init__(self, env, period, r_in_pipe, r_out_pipe, w_in_pipe, w_out_pipe, CMS_width):
        """
        r_in_pipe  : used to receive read result ACK
        r_out_pipe : used to return read result
        w_in_pipe  : used to receive write data
        w_out_pipe : used to indicate write completion
        """
        super(StrictPipe, self).__init__(env, period)

        # Top level interface
        self.r_in_pipe = r_in_pipe
        self.r_out_pipe = r_out_pipe
        self.w_in_pipe = w_in_pipe
        self.w_out_pipe = w_out_pipe

        # TODO: create and set hash functions
        self.hash1_fn = CRC32(env, period)
        self.hash2_fn = CRC32(env, period)
        self.hash3_fn = CRC32(env, period)

        self.hash1_cms = [0 for i in range(CMS_width)]
        self.hash2_cms = [0 for i in range(CMS_width)]
        self.hash3_cms = [0 for i in range(CMS_width)]

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
            virtual_time = self.get_virtual_time()
            rank = max(virtual_time, penalty)
            self.set_penalty(rank, pkt, hash1_idx, hash2_idx, hash3_idx)

            self.r_out_pipe.put((rank, q_id, pkt))
            yield self.r_in_pipe.get()

    def get_hash_idxs(self, pkt):

        hashTuple = 0

        if (pkt.haslayer(TCP)):
            hashTuple = pkt[IP].src + pkt[IP].dst + pkt[IP].proto + pkt[TCP].sport + pkt[TCP].dport
        elif (pkt.haslayer(UDP)):
            hashTuple = pkt[IP].src + pkt[IP].dst + pkt[IP].proto + pkt[UDP].sport + pkt[UDP].dport

        hash1_idx = self.hash1_fn.hash(hash_tuple)
        hash2_idx = self.hash2_fn.hash(hash_tuple)
        hash3_idx = self.hash3_fn.hash(hash_tuple)

    def get_penalty(self, hash1_idx, hash2_idx, hash3_idx):
        hash1_penalty = self.hash1_cms[hash1_idx]
        hash2_penalty = self.hash2_cms[hash2_idx]
        hash3_penalty = self.hash3_cms[hash3_idx]

        return min(hash1_penalty, hash2_penalty, hash3_penalty)

    def get_virtual_time(self):

    def set_penalty(self, rank, pkt, hash1_idx, hash2_idx, hash3_idx):
        # TODO: is this what we want? or do we want to add len if virtual_time is not max?
        self.hash1_cms[hash1_idx] = rank + len(pkt)
        self.hash2_cms[hash2_idx] = rank + len(pkt)
        self.hash3_cms[hash3_idx] = rank + len(pkt)

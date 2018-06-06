#!/usr/bin/env python

import simpy
from utils.hwsim_tools import *
from pifo_model import PIFO
from rank_pipes.stfq_cms import STFQCMSPipe

from utils.stats import flow_stats
import matplotlib
import matplotlib.pyplot as plt
import argparse

BUF_SIZE   = 2**17 # bytes
NUM_QUEUES = 4


class PIFO_tb(HW_sim_object):
    def __init__(self, env, period, pkts, q_ids):
        super(PIFO_tb, self).__init__(env, period)

        self.pifo_r_in_pipe = simpy.Store(env)
        self.pifo_r_out_pipe = simpy.Store(env)
        self.pifo_w_in_pipe = simpy.Store(env)
        self.pifo_w_out_pipe = simpy.Store(env)

        self.rank_r_in_pipe = simpy.Store(env)
        self.rank_r_out_pipe = simpy.Store(env)
        self.rank_w_in_pipe = simpy.Store(env)
        self.rank_w_out_pipe = simpy.Store(env)

        self.egress_link_rate = 10 # Gbps

        self.vt_tracker = VirtualTimeTracker()
        self.CMS_width = 1024
        self.rank_pipe = STFQCMSPipe(env, period, self.rank_r_in_pipe, self.rank_r_out_pipe, self.rank_w_in_pipe, self.rank_w_out_pipe, self.CMS_width, self.vt_tracker)

        self.pifo = PIFO(env, period, self.pifo_r_in_pipe, self.pifo_r_out_pipe, self.pifo_w_in_pipe, self.pifo_w_out_pipe, self.rank_w_in_pipe, self.rank_w_out_pipe, self.rank_r_in_pipe, self.rank_r_out_pipe, self.vt_tracker, buf_size=BUF_SIZE, num_queues=NUM_QUEUES)
        self.sender = PktSender(env, period, self.pifo_w_in_pipe, self.pifo_w_out_pipe, pkts, q_ids)
        self.receiver = PktReceiver(env, period, self.pifo_r_out_pipe, self.pifo_r_in_pipe, self.egress_link_rate)

        self.env.process(self.wait_complete(len(pkts)))

    def wait_complete(self, num_pkts):

        # wait for sender to send all pkts and pifo to be empty
        while len(self.sender.pkts) < num_pkts or len(self.pifo.values) > 0:
            yield self.wait_clock()

        self.pifo.sim_done = True
        self.receiver.sim_done = True


def plot_stats(pifo, input_pkts, output_pkts, egress_link_rate):
    # convert cycles to ns and remove metadata from pkt_list
    input_pkts = [(tup[0]*5, tup[2]) for tup in input_pkts]
    output_pkts = [(tup[0]*5, tup[2]) for tup in output_pkts]
    print 'input_pkts:  (start, end) = ({} ns, {} ns)'.format(input_pkts[0][0], input_pkts[-1][0])
    print 'output_pkts: (start, end) = ({} ns, {} ns)'.format(output_pkts[0][0], output_pkts[-1][0])
    flowID_tuple = ((IP, 'sport'),)
    input_stats  = flow_stats(flowID_tuple, input_pkts)
    output_stats = flow_stats(flowID_tuple, output_pkts)
    # create plots
    fig, axarr = plt.subplots(2)
    plt.sca(axarr[0])
    input_stats.plot_rates('Input Flow Rates', linewidth=3)
    plt.sca(axarr[1])
    output_stats.plot_rates('Output Flow Rates', ymax=egress_link_rate*1.5, linewidth=3)

    # plot queue sizes
    plt.figure()
    for i in range(pifo.num_queues):
        plt.plot([t*5 for t in pifo.times], pifo.q_size_stats[i], label='Queue {}'.format(i))
    plt.title('Queue Sizes')
    plt.ylabel('Size (B)')
    plt.xlabel('Time (ns)')
    plt.legend()

    font = {'family' : 'normal',
            'weight' : 'bold',
            'size'   : 22}
    matplotlib.rc('font', **font)
    plt.show()

def read_q_id_file(filename):
    q_ids = []
    with open(filename) as f:
        for line in f:
             try:
                 q_ids.append(int(line))
             except ValueError as e:
                 print >> sys.stderr, 'ERROR: Encountered invalid value in q_id file: {}'.format(line)
                 sys.exit(1)
    return q_ids

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pkts', type=str, help="pcap file that contains the packets to be applied in the simulation")
    parser.add_argument('qids', type=str, help="text file that contains the q_id that each packet should enter into")
    args = parser.parse_args()

    try:
        pkts = rdpcap(args.pkts)
    except IOError as e:
        print >> sys.stderr, "ERROR: failed to read pcap file: {}".format(args.pkts)
        sys.exit(1)

    q_ids = read_q_id_file(args.qids)

    env = simpy.Environment()
    period = 1
    tb = PIFO_tb(env, period, pkts, q_ids)
    env.run()

    print 'len(tb.sender.pkts) = {}'.format(len(tb.sender.pkts))
    print 'len(tb.receiver.pkts) = {}'.format(len(tb.receiver.pkts))
    plot_stats(tb.pifo, tb.sender.pkts, tb.receiver.pkts, tb.egress_link_rate)


if __name__ == '__main__':
    main()

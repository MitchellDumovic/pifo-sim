
# PIFO Simulator

A simple simulator that accepts as input a packet trace (pcap file) and
a text file that contains the queue ID for each packet. It will plot the input
and output flow rates as well as the queue sizes.

```
$ ./pifo_tb.py --help
usage: pifo_tb.py [-h] pkts qids [--cms] [--cmswidth N] [--naive]

positional arguments:
  pkts        pcap file that contains the packets to be applied in the
              simulation
  qids        text file that contains the q_id that each packet should enter
              into

optional arguments:
  --cms         enables use of count-min sketch in STFQ
  --cmswidth N  if --cms is used, this sets the width of the cmswidth (default = 8)
  --naive       enables use of first-come first-serve ranks instead of STFQ.
                if used in conjunction with --cms, CMS will be enabled
```

new files:
---------
naive.py: defines a first-come first serve rank computation
stfq_cms.py: defines a start time fair queueing rank computation with the use of
             count-min sketch to track per-flow statistics
stfq.py: defines a start time fair queueing rank computation with perfect per-flow
         statistics
test_data/gen_testdata.py: generates pcap files for test traffic patterns
utils/avg_rate_stats.py: calculates statistics across output flow rates, including
                         average rate, variance, max, min
collision_checker.py: used to check collisions across hash functions for different flow tuples

--------------
updated files:
--------------
pifo_tb.py: changed to support use of STFQ, STFQCMS, and FCFS pipes
utils/hwsim_tools.py: added VirtualTimeTracker()
utils/stats.py: new method of calculating input and output data rates. more accurate


--------------
Log of changes
--------------

6/4/18

We are using pifo-sim to model a pifo at the output of our P4 program. We pass in pkts and ranks that are output by our P4 program and it plots the output rates of the flows given these ranks in the pifo.

stats.py: fixed a small bug to allow for slicing of a range(...) by converting to list first: list(range(...))

6/5/18

stfq.py: new file that models a Start Time Fair Queueing Rank Computation pipe. CMS hashes still TBD.
pifo_tb.py: changed to use STFQPipe instead of StrictPipe; initialize virtual time tracker and pass to STFQPipe; CMS width defined in this file and passed to STFQPipe
hwsim_tools.py: added VirtualTimeTracker() class definition which defines an object that holds virtual time. can be updated by PIFO and read by STFQPipe. Should be passed into both

6/5/18
stfq.py: changed file to be STFQ without CMS, but with perfect memeory
stfq_cms.py: added CMS implementation of STFQ using crcmod module to import CRC hash functions

6/6/18
gen_testdata.py: made this file to generate test pcap files to model traffic

6/9/18
gen_testdata.py: added many more tests
stfq_cms.py: updated UPDATE policy within STFQCMS to more accurately reflect tracking of per-flow statistics

6/11/18
utils/stats.py: reworked how rates were being calculated so that every flow has a rate across the same
                interval as determined by avg_interval. also more accurately reflects rates (fixed bug of not adding len(packet) in new interval)
utils/avg_rate_stats.py: created this file. uses same new rate calculation method. calculates statistics across output flow rates, including
                         average rate, variance, max, min. graphs new statistics on third subplot

6/12/18
utils/stats.py: updates to change how graphs look
utils/avg_rate_stats.py: updated so that variance is being written to file instead of being graphed

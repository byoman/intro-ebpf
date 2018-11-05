from bcc import BPF
from time import sleep
import sys
import argparse

#args

path = "c"

parser = argparse.ArgumentParser()
parser.add_argument("func_name", help="name of the user function you want to trace")
parser.add_argument("-p", "--path", nargs=1, default="c", action="store",dest="path", help="path to the .so of the executable containing the function you want to trace")

args = parser.parse_args()
if args.path:
	path = args.path[0]

# load BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

BPF_HASH(countMap, int, u64);
int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    int key;
    bpf_probe_read(&key, sizeof(key), &PT_REGS_PARM1(ctx));
    countMap.increment(key);
    return 0;
};
"""

b = BPF(text=bpf_text)

b.attach_uprobe(name=path, sym=args.func_name, fn_name="count")

# header
print("Tracing %s... Hit Ctrl-C to end." % (args.func_name))

#sleep until Ctrl-C
try:
   sleep(99999999)
except KeyboardInterrupt:
   pass

#print output
print("%10s %10s" % ("ARG1", "NBCALLS"))
counts = b["countMap"]
for k, v in counts.items():
	print("%10d %10lu" % (k.value, v.value))

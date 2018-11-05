# Light introduction to BPF / eBPF

EBPF (or simply BPF) is a highly flexible and efficient virtual
machine-like construct in the Linux kernel allowing to execute bytecode
at various hook points in a safe manner. It is used in a number of Linux
kernel subsystems, most prominently networking, tracing and security.

How does BPF works? How can we do userland tracing with it? What changes
have allowed the framework to be that much extensible?
These are the notes I made while trying to answer these questions (in the notes.md file).

Note: this document is the result of much research and reading of many articles.
Thus, all articles that I read or whose words I used are available in the sources.md file

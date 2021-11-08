This package uses code under the GPL2 license.

# EBPF/XDP Software
EBPF/XDP is software that filters networking packets in kernel space.
This EBPF filter and userspace tool was produced for for the means of handling potential DoS attacks against an SPA port.

The xdp-anti-dos repository consists of a userspace application, and a kernelspace file that attaches to an early point in the Netfilter
framework. The xdp-process is used to load the xdp_prog_kern file into kernelspace. Ingress packets are checked against a
set of rules to determine whether they should be passed through to the network stack, or dropped. This particular implementation
checks for UDP packets on our specified SPA port, confirms it is of correct length, and protects against DDoS on the SPA port.

xdp tutorial and workshop that some of the common tools have been borrowed from:
<https://github.com/xdp-project/xdp-tutorial>
<https://github.com/ns1/xdp-workshop>

An interesting read about Single Packet Authentication can be found here:
<https://network-insight.net/2019/06/zero-trust-single-packet-authorization-passive-authorization/>
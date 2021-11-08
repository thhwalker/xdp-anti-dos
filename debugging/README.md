# EBPF/XDP Debugging

Debugging the XDP kernelspace program can be a pain. This is a modded version of the production code that you can use to modify values, check variables etc.

bpf_debug will give you the ability to print information from the kernelspace.

To do your testing, make the necessary changes to `helloworld_kern.c`, then run `make`.

When your program is created, run the following command to attach it to your loopback interface.

```bash
sudo ip link set dev lo xdp obj helloworld_kern.o sec xdp_pass
```

Once you have attached your xdp program, run the following command; this will start reading from a buffer that will print your debug strings.

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

When you have finished debugging, remove your program from the loopback interface using the following command.

```bash
sudo ip link set dev lo xdp off
```

To generate traffic, you may use a handy packet sending GUI like [pathETH](https://github.com/jemcek/packETH), however, the choice is yours.

Code loosely based on 01-helloworld workshop located at <https://github.com/ns1/xdp-workshop>

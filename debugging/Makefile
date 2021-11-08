CC ?= gcc
LLC ?= llc
CLANG ?= clang

KERNEL_TARGET = helloworld_kern
KERNEL_TARGET_OBJECT = ${KERNEL_TARGET:=.o}
KERNEL_TARGET_LLC_OBJECT = ${KERNEL_TARGET:=.ll}

CFLAGS += "-I/usr/include/x86_64-linux-gnu"

.PHONY: all
all: $(KERNEL_TARGET_OBJECT) $(USER_TARGET)

$(KERNEL_TARGET_OBJECT): %.o: %.c $(KERNEL_TARGET_DEPS)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
		-Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -g -o $(KERNEL_TARGET_LLC_OBJECT) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(KERNEL_TARGET_LLC_OBJECT)

.PHONY: clean
clean:
	rm -f *.ll *.o $(USER_TARGET)
CC ?= gcc
LLC ?= llc
CLANG ?= clang

KERNEL_TARGET = xdp_prog_kern
KERNEL_TARGET_OBJECT = ${KERNEL_TARGET:=.o}
KERNEL_TARGET_LLC_OBJECT = ${KERNEL_TARGET:=.ll}
KERNEL_TARGET_DEPS = xdp_prog_kern.h

USER_TARGET = xdp_process
USER_TARGET_DEPS = xdp_process.h 

COMMON_OBJS := ../common/common_params.o ../common/common_user_bpf_xdp.o

CFLAGS := "-Icommon"
CFLAGS += "-I/usr/include/x86_64-linux-gnu"

.PHONY: all
all: $(KERNEL_TARGET_OBJECT) $(USER_TARGET)

$(USER_TARGET): %: %.c $(USER_TARGET_DEPS) $(COMMON_OBJS)
	$(CC) \
		$(CFLAGS) \
		-L$(LIBBPF_OUTPUT_DIR) \
		-Wall \
		-Wno-unused-variable \
		-Wno-unused-function \
		-O2 -g -o $@ $< $(COMMON_OBJS) \
		-lbpf -lelf

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
.PHONY: all
all:
	(cd common; make)
	(cd xdp-ebpf; make)

.PHONY: clean
clean:
	(cd common; make clean)
	(cd xdp-ebpf; make clean)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
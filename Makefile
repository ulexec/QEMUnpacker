CC = gcc
LD32 = -m32
LDFLAGS = --static 

all: agents build_examples

agents:
	${MAKE} -C ./agent

build_examples:
	${MAKE} -C ./examples

.PHONY: clean
clean:
	rm ./examples/*.dyn 
	rm ./examples/*.packed 
	rm ./agent/*i386* ./agent/*x86_64* ./agent/*arm*
	rm ./agent/dumped* || true
	rm ./agent/emulate


CC = gcc
LD32 = -m32
LDFLAGS = --static 
SUBDIR = ./examples

all: agent emulate build_examples

agent: 
	${CC} $@.c -o $@64
	${CC} $@.c ${LD32} -o $@32

emulate:
	${CC} $@.c -lpthread -lunicorn -o $@

build_examples:
	${MAKE} -C ${SUBDIR}

.PHONY: clean
clean:
	rm ${SUBDIR}/*.dyn 
	rm ${SUBDIR}/*.packed 
	rm *32* *64*
	rm dumped* || true
	rm emulate


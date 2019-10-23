CC = gcc
LD32 = -m32
LDFLAGS = --static 

all: agent emulate

agent: 
	${CC} $@.c -o $@64
	${CC} $@.c ${LD32} -o $@32

emulate:
	${CC} $@.c -lpthread -lunicorn -o $@


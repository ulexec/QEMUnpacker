CC = gcc
LD32 = -m32
LDFLAGS = --static 

all: agent emulate

agent: 
	${CC} $@.c -o $@-x86_64
	${CC} $@.c ${LD32} -o $@-i386
	arm-linux-gnueabi-${CC} -static $@.c -o $@-arm
emulate:
	${CC} $@.c -lpthread -lunicorn -o $@


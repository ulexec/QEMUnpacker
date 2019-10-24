CC = gcc
LD32 = -m32
LDFLAGS = --static 

all: sample wait

sample:
	${CC} $@.c -o $@-x86_64.dyn
	${CC} $@.c ${LDFLAGS} -o $@-x86_64.packed 
	upx $@-x86_64.packed > /dev/null
	${CC} $@.c ${LD32} -o $@-i386.dyn
	${CC} $@.c ${LDFLAGS} ${LD32} -o $@-i386.packed
	upx $@-i386.packed > /dev/null
	arm-linux-gnueabi-${CC} $@.c ${LDFLAGS} -o $@-arm.packed
	upx $@-arm.packed > /dev/null
wait:
	${CC} $@.c -o $@-x86_64.dyn 
	${CC} $@.c ${LDFLAGS} -o $@-x86_64.packed 
	upx $@-x86_64.packed > /dev/null
	${CC} $@.c ${LD32} -o $@-i386.dyn
	${CC} $@.c ${LDFLAGS} ${LD32} -o $@-i386.packed
	upx $@-i386.packed > /dev/null
	arm-linux-gnueabi-${CC} $@.c ${LDFLAGS} -o $@-arm.packed
	upx $@-arm.packed > /dev/null	
	

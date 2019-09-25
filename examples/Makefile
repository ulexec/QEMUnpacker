CC = gcc
LD32 = -m32
LDFLAGS = --static 

all: sample wait

sample:
	${CC} $@.c -o $@64.dyn
	${CC} $@.c ${LDFLAGS} -o $@64.packed 
	upx $@64.packed > /dev/null
	${CC} $@.c ${LD32} -o $@32.dyn
	${CC} $@.c ${LDFLAGS} ${LD32} -o $@32.packed
	upx $@32.packed > /dev/null
	
wait:
	${CC} $@.c -o $@64.dyn 
	${CC} $@.c ${LDFLAGS} -o $@64.packed 
	upx $@64.packed > /dev/null
	${CC} $@.c ${LD32} -o $@32.dyn
	${CC} $@.c ${LDFLAGS} ${LD32} -o $@32.packed
	upx $@32.packed > /dev/null
	

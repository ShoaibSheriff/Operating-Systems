obj-m += sys_cpenc.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcpenc cpenc

xcpenc: xcpenc.c e_struct.h
	gcc -Wall -Werror -lssl -lcrypto -I$(INC)/generated/uapi -I$(INC)/uapi xcpenc.c -o xcpenc

cpenc:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcpenc
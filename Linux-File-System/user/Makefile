INC=/lib/modules/$(shell uname -r)/build/arch/x86/include
INC2=/lib/modules/$(shell uname -r)/build/include/linux/bkpfs/

all: bkpctl

bkpctl: bkpctl.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi -I$(INC2) bkpctl.c -o bkpctl

clean:
	rm -f bkpctl
	rm -f test_create_file

// SPDX-License-Identifier: GPL-2.0+
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "e_struct.h"
#include <unistd.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <openssl/md5.h>

# define MD5_SIZE 16

static bool parse(E_Struct *e_struct, int argc, char **argv)
{
	
	int opt, index, ii; 
	char* next = NULL;
	bool error = false;
	unsigned char hash[MD5_DIGEST_LENGTH];
	
	while((opt = getopt(argc, argv, ":p:e:d:c:")) != -1)  
    {  
        switch(opt)  
        {  
 
            case 'p':  

				e_struct->keybuf = (void *) malloc(MD5_DIGEST_LENGTH);
				if (strlen(optarg) < 6) {
					printf("Password too short.");
					error = true;
					break;
				}
				
				MD5((const unsigned char *)optarg, strlen(optarg), hash);
				for (ii = 0; ii < 16; ii++) {
					*((char*)e_struct->keybuf + ii) = hash[ii];
				}
				
				e_struct->keylen = MD5_DIGEST_LENGTH;
                break;  
			case 'c': 
			
				if (e_struct->flags == 1 || e_struct->flags == 2) {
					error = true;
					break;
				}
				e_struct->flags = 4;

                index = optind-1;
				while(index < argc){
					next = strdup(argv[index]);
					index++;
					if(next[0] != '-'){
						if (e_struct->infile == NULL) {
							e_struct->infile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->infile, next);
						} else if (e_struct->outfile == NULL) {
							e_struct->outfile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->outfile, next);
						}
					}
					else break;
				}
				break;
			case 'd': 

				if (e_struct->flags == 1 || e_struct->flags == 4) {

					error = true;
					break;
				}
			
				e_struct->flags = 2;

                index = optind-1;
				while(index < argc){
					next = strdup(argv[index]);
					index++;
					if(next[0] != '-'){
						if (e_struct->infile == NULL) {
							e_struct->infile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->infile, next);
						} else if (e_struct->outfile == NULL) {
							e_struct->outfile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->outfile, next);
						}
					}
					else break;
				}
				break;
			case 'e':

				if (e_struct->flags == 2 || e_struct->flags == 4) {
					error = true;
					break;
				}
			
				e_struct->flags = 1;

                index = optind-1;
				while(index < argc){
					next = strdup(argv[index]);
					index++;
					if(next[0] != '-'){
						if (e_struct->infile == NULL) {
							e_struct->infile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->infile, next);
						} else if (e_struct->outfile == NULL) {
							e_struct->outfile = (char *) malloc
								(strlen(next) + 1);
							strcpy(e_struct->outfile, next);
						}
					}
					else break;
				}

                break; 
            case ':':  
                printf("option needs a value\n");  
                break;  
            case '?':  
                printf("unknown option: %c\n", optopt); 
                break;  
        }  
    }
	
	return error;
}

static void showHelp() {
	printf("%s", "Usage: {-e|-d|-c} {-p PASSWORD} infile outfile\n");
	printf("%s","{-e|-d} : Use -e to encrypt, -d to decrypt and -c to just copy.\n");
	printf("%s","-p : Use to give password. Password is required for encrypt/decrypt\n");
	printf("%s","-h : Use to display this help message\n");
	printf("%s","infile : Use to specify input file name (along with path)\n");
	printf("%s","outfile : Use to specify output file name (along with path)\n"); 
}

int main(int argc, char *argv[])
{
	int ret = 0;
	E_Struct *e_struct = NULL;
	
	if (argc == 0 || strcmp(argv[1], "-h") == 0) {
		showHelp();
		ret = 0;
		goto out;
	}

	e_struct = (E_Struct *)malloc(sizeof(E_Struct));

	memset(e_struct, 0, sizeof(E_Struct));
	
	e_struct->flags = 0;
	e_struct->infile = NULL;
	e_struct->outfile = NULL;
	e_struct->keybuf = NULL;

	if(parse(e_struct, argc, argv)) {
		printf("Invalid input\n");
		ret = -EINVAL ;
		goto out;
	}

	if (e_struct->flags == 0) {
		printf("Invalid input\n");
		ret = -EINVAL ;
		goto out;
	}
	
	if ((e_struct->flags == 4) && (e_struct->infile == NULL || e_struct->outfile == NULL)) {
		printf("Invalid inputs\n");
		ret = -EINVAL ;
		goto out;
	}
	
	if ((e_struct->flags == 1 || e_struct->flags == 2) && (e_struct->infile == NULL || e_struct->outfile == NULL || e_struct->keybuf == NULL)) {
		printf("Invalid inputs\n");
		ret = -EINVAL ;
		goto out;	
	}
	
	if (access(e_struct->infile, F_OK) != 0) {
		printf("Input file does not exist\n");
		ret = -ENOENT;
		goto out;
	}

	if (access(e_struct->infile, R_OK) != 0) {
		printf("File cant be read\n");
		ret = -1;
		goto out;
	}

	if ((e_struct->flags != 4) && strlen(e_struct->keybuf) < 6) {
		printf("Password too short\n");
		ret = -EINVAL ;
		goto out;
	}
	
	int rc = 0;
	rc = syscall(__NR_cpenc, (void *)e_struct);

	if (rc < 0) {
		printf("Error no : %d\n", rc);
		ret = -1;
		goto out;
	}

	out:
	if (e_struct && e_struct->infile)
		free(e_struct->infile);
	if (e_struct && e_struct->outfile)
		free(e_struct->outfile);
	if (e_struct && e_struct->keybuf)
		free(e_struct->keybuf);
	if (e_struct)
		free(e_struct);
	return ret;
}

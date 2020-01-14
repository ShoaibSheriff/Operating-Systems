#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <stdbool.h>
#include <errno.h>

#include <bkpfs_common.h>

#define CMD_LIST_VERSIONS 1
#define CMD_DELETE_VERSION 2
#define CMD_VIEW_VERSION 4
#define CMD_RESTORE_VERSION 8


int setBackupVersion(bkps_ioctl_args *ioctl_args, char *optarg) {

    char *str_part;

    if(strcmp(optarg, "n") == 0) {
        ioctl_args->bkp_file_version = FILE_LATEST;
        return 1;    
    }

    if(strcmp(optarg, "o") == 0) {
        ioctl_args->bkp_file_version = FILE_OLDEST;
        return 1;    
    }

    if(strcmp(optarg, "a") == 0) {
        ioctl_args->bkp_file_version = FILE_ALL;
        return 1;    
    }

    ioctl_args->bkp_file_version = strtol(optarg, &str_part, 10);
    if (strlen(str_part) != 0) {
        printf("Could not read version\n");
        return 0;
     } else {
        return 1;
     }
      
}

int parseData(int argc, char *argv[], bkps_ioctl_args *ioctl_args, char **parent_dir, char **file_full_path) {

    int opt;
    int cmd = -1;

    while((opt = getopt(argc, argv, "ld:v:r:")) != -1)  
    {  
        switch(opt)  
        {  
            case 'l':  
                cmd = CMD_LIST_VERSIONS;
                break;  
            case 'd':  
                cmd = CMD_DELETE_VERSION;
                //printf("version: %s\n", optarg); 
                if (!setBackupVersion(ioctl_args, optarg))
                    return -1;
                break;

            case 'v':  
                cmd = CMD_VIEW_VERSION;
                //printf("version: %s\n", optarg);  
                if (!setBackupVersion(ioctl_args, optarg))
                    return -1;
                break;  

            case 'r':  
                cmd = CMD_RESTORE_VERSION;
                //printf("version: %s\n", optarg);  
                if (!setBackupVersion(ioctl_args, optarg))
                    return -1;
                break;

            case ':':  
                printf("missing paramter\n"); 
                return -1; 
            case '?':  
                printf("unknown option: %c\n", optopt); 
                return -1;
        }  
    }

    if (ioctl_args == NULL) {
        return -1;
    }

    for(; optind < argc; optind++){ 

        ioctl_args->file_name = (char *)malloc(strlen(basename(argv[optind])) + 1);
        strcpy(ioctl_args->file_name, basename(argv[optind]));
        // printf("file_name: %s\n", ioctl_args->file_name); 

        *parent_dir = dirname(argv[optind]);    

        ioctl_args->file_name_length = strlen(ioctl_args->file_name);
        // printf("file_name_length: %d\n", ioctl_args->file_name_length);
        
    }

    return cmd;
}

int main(int argc, char *argv[])
{

    char **parent_dir = NULL;
    char **file_full_path = NULL;
    char *temp_file_name = "ioctl.temp";

    char *viewable_file = ".temp";

    char *temp_file_full_path;
    char *view_buffer;

    char *view_command = "vi -R .temp";

    int cmd = -1;

    int fd; 
    int ret = 0;
    bool version_read = false;

    struct bkps_ioctl_args *ioctl_args = NULL;
    ioctl_args = (bkps_ioctl_args *)malloc(sizeof(struct bkps_ioctl_args));

    parent_dir = malloc(sizeof(char*));
    file_full_path = malloc(sizeof(char*));

    cmd = parseData(argc, argv, ioctl_args, parent_dir, file_full_path);
    if (cmd == -1) {
        printf("Error in params\n");
        errno = EINVAL;
        return -1;
    }

    temp_file_full_path = malloc(strlen(*parent_dir) + strlen(temp_file_name) + 2);
    sprintf(temp_file_full_path, "%s/%s", *parent_dir, temp_file_name);
    // printf("file passed is %s\n", temp_file_full_path);

    fd = open(temp_file_full_path, O_RDWR | O_CREAT);
    if (fd == -1)
    {
        printf("Error opening file\n");
        ret =-1;
        goto out;
    }

    // printf("%d\n", cmd);

    switch(cmd) {
        case CMD_LIST_VERSIONS:
           
            ioctl_args->bkp_files_view = malloc(getpagesize());

            ret = ioctl(fd, IOCTL_LIST_VERSIONS, ioctl_args); 

            if (ret > 0) {
                printf("Backup versions available are : %.*s\n", ret, ioctl_args->bkp_files_view);
            } else {
                errno = -ret;
                ret = -1;
            }

            break;

        case CMD_DELETE_VERSION:
            ret = ioctl(fd, IOCTL_DELETE_VERSION, ioctl_args); 
            if (ret >= 0) {
                printf("Delete Succesful\n");
            } else {
                errno = -ret;
                ret = -1;
            }
            break;

        case CMD_VIEW_VERSION:
            view_buffer = (char *)malloc(getpagesize());
            ioctl_args->read_offset = 0;
            ioctl_args->buf = view_buffer;

            FILE *fp;

            fp = fopen(viewable_file, "w");

            do {
                ret = ioctl(fd, IOCTL_VIEW_VERSION, ioctl_args);
                if (ret > 0) {
                    version_read = true;
                    fprintf(fp, "%.*s", ret, ioctl_args->buf);   
                }

                ioctl_args->read_offset = ioctl_args->read_offset + ret;
            } while (ret > 0);

            fclose(fp);

            if (version_read) {
                ret = 0
                system(view_command);
            } else {
                ret = -1;
            }

            break;
        case CMD_RESTORE_VERSION:
            ret = ioctl(fd, IOCTL_RESTORE_VERSION, ioctl_args); 
            if (ret >= 0) {
                printf("Restore Succesful\n");
                ret = 0;
            } else {
                errno = -ret;
                ret = -1;
            }
            break;
        default:
            printf("Error in parameters\n");
    }

    close(fd);
    remove(temp_file_full_path);
    remove(viewable_file);

out :
    free(parent_dir);
    free(file_full_path);
    free(ioctl_args);

    if (ret < 0) {
        printf("Error code : %d\n", errno);
    }

    return ret;
}
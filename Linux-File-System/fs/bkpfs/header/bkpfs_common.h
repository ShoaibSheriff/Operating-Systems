#ifndef BKPFS_IOCTL_H
#define BKPFS_IOCTL_H

#include <linux/ioctl.h>

#define FILE_LATEST -2
#define FILE_OLDEST -1
#define FILE_ALL -3

struct bkp_file_list_entry_user {
	char *filename;
	char *ct_time;
};

typedef struct bkps_ioctl_args {
    char *file_name;
    int file_name_length;
    int bkp_file_version;

    char *buf;
    int read_offset;

    char *bkp_files_view;
    // long[100] ct_times;

} bkps_ioctl_args;

#define IOCTL_LIST_VERSIONS _IOWR(4421, 'a', void *)
#define IOCTL_DELETE_VERSION _IOW(4423, 'a', void *)
#define IOCTL_VIEW_VERSION _IOW(4425, 'a', void *)
#define IOCTL_RESTORE_VERSION _IOW(4427, 'a', void *)

#endif
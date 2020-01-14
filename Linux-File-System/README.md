
## Aim : 
To create an auto back up stackable file system layer "bkpfs". File system should have the utility commands to i) list available versions of a file, ii) delete newest, oldest or all versions of a file iii) view a backup version and iv) restore contents of a specified version to the file.

## Files :

1) fs/bkpfs - This folder contains all the files of the loadable kernel module.
2) user - This folder contains all the user level codes.
3) header/bkpfs_common.h - This is the common header file. It contains the IOCTL definition.


## Kernel level code

#### 1) Mount options :

The user mounts the file system with :

	mount -t bkpfs -o maxver=3 /source /mountpoint
The "maxver" command specifies the maximum number of backup versions that can be stored for a specific file. 

	mount -t bkpfs -o maxver=3,maxsize=1 /test/hw2 /test/mnt/bkpfs
"maxsize" specifies maximum size in MB that is available to the file system to store all the backup versions for a single file.

These values are stored as metadata with the superblock. "maxver" is stored as "max_backup_version". "maxsize" is stored as "max_size_kb"(after conversion).

#### 2) BKP directory :

a) Create 

All the backup files are stored inside a backup folder. The directory is located under the same parent as the original file. The name of the directory is set as : ".bak.{ORIGINAL_FILE_NAME}"

For example, if filename is "123.txt", then the name of the backup directory is ".bak.123.txt".

The directory is created inside "bkpfs_create". This is the method to handle inode ".create". On succesful creation of inode, we first create a negative dentry.
We then use this to confirm that no earlier directory with the same name exists. If no directory exists, we use "vfs_mkdir" to create the bkp directory.

b) Attributes :

To store the current state of the backups, we use extended attributes of the directory. We use "vfs_getxattr" and "vfs_setxattr" manipulate it. 
The actual data stored is a struct with variables : "max_version", "min_version" and "size_kb"(Extra credits).
max_version stores the count(bkp file names are integers) of the newest available backup file. 
min_version stores the count(bkp file names are integers) of the oldest available backup file.
size_kb stores the total size taken up by all of the currently available backup files.

c) Hide :

The bkp directory is a private data structure that belongs to the file system. Hence, the user should not be be able to manipulate it easily. 
One simple way to acheive this is to hide the backup directory from being shown in a "ls" or even a "ls -la". 

To acheive this behavior, we modify the behavior of the "filldir" method. This method is called by "readdir" (which ls uses), for every item inside the main parent directory. By returning null here, we force the parent directory to hide the bkp directory.


#### 3) BKP file :

a) Creation :

The backup files should be created automatically every time the user writes to a new/ existing file. Hence, we handle backup file creation at "bkpfs_write".
This is the method that is invoked on file ".write". We first verify that the original file was well written to. Next, check if the backup directory exists.
If yes, we created a negative dentry for the file and then use "vfs_create" to create the actual file. If this succeds, "vfs_copy_file_range" can be used to
effeciently copy the original file contents to the newly created backup file.

b) Deletion :

The automatic deletion of the files is also handled at "bkpfs_write". If in here, we succeed in creating a new file, we use the superblock metadata and the backup folder metadata to check if a deletion is required.

If yes, we begin deleting the oldest backup files, until both our number constarint(maxver) and size constraint(maxsize) are met.

c) Naming :

For the backup files, we use a very simple naming convention. A new file created is always named :
(bkp_directory ->max_version)mod(2 * superblock->max_backup_version) + 1. 

For example, if max_backup_version = 3, each line below signifies a new backup and shows the available backup file names.
The latest files are on the left.

1
2 1
3 2 1
4 3 2
5 4 3
6 5 4
1 6 5 (since 6%(2*3) + 1 = 1)
2 1 6 and so on.

This file naming scheme is quite simple and avoids having to rename the backup file versions everytime.

However ! This scheme can be very confusing to the user since we use numbers. The user may look at "2 1 6" and assume 6 is latest. So we use a slightly different naming scheme when communicating with the user.

Using above example, the user sees 
the versions (list version command) as :

1  --> 1
2 1 --> 2 1
3 2 1 --> 3 2 1
4 3 2 --> 4 3 2
5 4 3 --> 5 4 3
6 5 4 --> 6 5 4
1 6 5 --> 7 6 5
2 1 6 --> 8 7 6  and so on.

To translate, we simple use modulus of 2 * max_backup_version. Hence, 8 7 6 translates to 2 1 6. The third options is 6, since file system avoids 0 and hence, re-adds the modulus.

This inherently also has an issue since eventually, we run out of numbers. Thus, we reset user version file names when we cross 6 times max_backup_version

So, after, 
19 18 17 (since 19 > 6 * 3(max_backup_version)) 
we get,
7 6 5 (19%(2 * 3) + (2 * 3) = 7)

For translation -> 19 18 17 is 1 6 5. 7 6 5 is also 1 6 5. Hence, the naming scheme is maintained.

4 ) BKPCTL :

This is the user level command available to interact with the file system.

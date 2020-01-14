/*
 * Copyright (c) 1998-2017 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2017 Stony Brook University
 * Copyright (c) 2003-2017 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "bkpfs.h"
#include <linux/sched/signal.h>
#include <asm/uaccess.h>
#include <linux/namei.h>

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include<linux/slab.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/path.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/namei.h>
#include <crypto/hash.h>   
#include <linux/init.h>     
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))

int lenHelper(unsigned int x) {
    if (x >= 100000)     return 6;
    if (x >= 10000)      return 5;
    if (x >= 1000)       return 4;
    if (x >= 100)        return 3;
    if (x >= 10)         return 2;
    return 1;
}

static int get_bkp_folder_dentry(struct dentry *lower_parent_dentry, struct vfsmount *mnt, 
	const unsigned char *org_file_name, struct dentry **bkp_folder_dentry) {

	int ret = 0;

	char *folder_name = NULL;
	struct qstr this;
	struct path lower_path_bkp_dir;

	UDBG;

	folder_name = kmalloc(strlen(BKP_FOLDER_PREFIX) + strlen(org_file_name) + 1, GFP_KERNEL);
	strcpy(folder_name, BKP_FOLDER_PREFIX);
	strcat(folder_name, org_file_name);

	printk("f_name %s", folder_name);

	this.name = folder_name;
	this.len = strlen(this.name);
	this.hash = full_name_hash(lower_parent_dentry, this.name, this.len);
	*bkp_folder_dentry = d_lookup(lower_parent_dentry, &this);
	if (*bkp_folder_dentry) {
		printk("Bkp folder found.");
		goto out;
	}

	*bkp_folder_dentry = d_alloc(lower_parent_dentry, &this);
	if (!*bkp_folder_dentry) {
		// dput(*bkp_folder_dentry);
		ret = -ENOMEM;
		UDBG;
		goto out;
	}
	d_add(*bkp_folder_dentry, NULL); /* instantiate and hash */

	ret = vfs_path_lookup(lower_parent_dentry, mnt, folder_name, 0,
			      &lower_path_bkp_dir);

	if (!ret) {
		printk("Bkp folder found.");
		*bkp_folder_dentry = lower_path_bkp_dir.dentry;
		goto out;
	}

	if (ret == -ENOENT) {
		printk("BKP folder not found.");
	} else {
		printk("Unknown error %d", ret);
	}

out :
	if (folder_name)
		kfree(folder_name);

	return ret;

}

static int get_dentry(struct dentry *parent_folder_dentry, char *file_name, struct vfsmount *mnt, struct dentry **dentry) {

	struct path *dentry_path;
	int ret;
	struct qstr this;

	this.name = file_name;
	this.len = strlen(this.name);
	this.hash = full_name_hash(parent_folder_dentry, this.name, this.len);
	*dentry = d_lookup(parent_folder_dentry, &this);
	if (*dentry) {
		UDBG;
		ret = 0;
		printk("dentry found");
		goto out;
	}

	*dentry = d_alloc(parent_folder_dentry, &this);
	if (!*dentry) {
		dput(*dentry);
		ret = -ENOMEM;
		UDBG;
		goto out;
	}
	d_add(*dentry, NULL); /* instantiate and hash */

	ret = vfs_path_lookup(parent_folder_dentry, mnt, (*dentry)->d_name.name, 0,
			      dentry_path);
	if (!ret) {
		*dentry = dentry_path->dentry;
		printk("dentry found");
		goto out;
	}

	if (ret == -ENOENT) {
		// d_drop(*dentry);
		// dput(*dentry);
		printk("Dentry not found");
		goto out;
	}

	printk("Error %d", ret);

out :
	return ret;
}

int delete_dentry(struct dentry *bkp_folder_dentry, struct vfsmount *mnt, int bkp_file_version) {

	int err;
	struct dentry **bkp_file_dentry_ptr;
	struct dentry *bkp_file_dentry;

	char* filename_to_delete;
	int size = 0;

	filename_to_delete = kmalloc(lenHelper(bkp_file_version), GFP_KERNEL);
	sprintf(filename_to_delete, "%d", bkp_file_version);

	bkp_file_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
	err = get_dentry(bkp_folder_dentry, filename_to_delete, mnt, bkp_file_dentry_ptr);
	if (err) {
		UDBG;
		goto out;
	}

	bkp_file_dentry = *bkp_file_dentry_ptr;

	UDBG;

	printk("Try to delete %s", filename_to_delete);
	size = bkp_file_dentry->d_inode->i_size;

	err = vfs_unlink(d_inode(bkp_folder_dentry), bkp_file_dentry, NULL);
	if (err == 0  || (err == -EBUSY && bkp_file_dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		printk("delete successful");
		d_delete(bkp_file_dentry);
		dput(bkp_file_dentry);
		err = size;
		goto out;
	}
	if (err) {
		printk("Error while deleting");
	}

out:
	if (filename_to_delete)
		kfree(filename_to_delete);

	if (bkp_file_dentry_ptr)
		kfree(bkp_file_dentry_ptr);

	return err;
}

static ssize_t bkpfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	UDBG;

	lower_file = bkpfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static u16 get_wrapped_name_mk(struct dentry *org_dentry, u16 current_version) {

	struct bkpfs_global_meta_data *global_meta_data;
	u16 total_max_backup;
	u16 temp = 0;

	//check if delete required
	global_meta_data = &BKPFS_SB(org_dentry->d_sb)->global_meta_data;
	if (global_meta_data == NULL) {
		printk("No global bkp meta data.");
		return -1;
	}

	total_max_backup = global_meta_data->max_backup_version;
	temp = (current_version %(2 * total_max_backup));

	return temp;

}

static u16 get_wrapped_name(struct dentry *org_dentry, u16 current_version) {

	struct bkpfs_global_meta_data *global_meta_data;
	u16 total_max_backup;
	u16 temp = 0;

	//check if delete required
	global_meta_data = &BKPFS_SB(org_dentry->d_sb)->global_meta_data;
	if (global_meta_data == NULL) {
		printk("No global bkp meta data.");
		return -1;
	}

	total_max_backup = global_meta_data->max_backup_version;
	temp = (current_version %(2 * total_max_backup));

	if (temp == 0) {
		temp = temp + 2 * total_max_backup;
	}

	return temp;

}

static ssize_t bkpfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err0;
	int err;

	struct file *lower_orig_file;
	struct dentry *org_dentry = file->f_path.dentry;

	// hidden dir
	struct dentry *lower_parent_dentry;
	struct dentry **bkp_folder_dentry_ptr;
	struct dentry *bkp_folder_dentry;

	//hidden dir meta-data
	struct lower_dentry_meta_data *dentry_meta_data = NULL;
	u16 current_bkp_version;

	//new bkp file
	char* new_bkp_file_name;
	struct dentry *new_bkp_file_dentry;
	loff_t pos = 0;
	loff_t pos2 = 0;
	struct file *file_in_read;
	struct path *temp_path_in;
	struct file *file_out;
	struct path *temp_path_out;
	loff_t file_size;

	int old_size = 0;
	int new_size = 0;
	int max_size = 0;

	//check if delete required
	struct bkpfs_global_meta_data *global_meta_data;
	u16 total_max_backup;
	u16 tmp_for_delete;

	int temp;

	UDBG;

	lower_orig_file = bkpfs_lower_file(file);
	err0 = vfs_write(lower_orig_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err0 < 0) {
		goto out;
	}

	fsstack_copy_inode_size(d_inode(org_dentry),
				file_inode(lower_orig_file));
	fsstack_copy_attr_times(d_inode(org_dentry),
				file_inode(lower_orig_file));

 	 if(strncmp(org_dentry->d_name.name, BKP_FOLDER_PREFIX, strlen(BKP_FOLDER_PREFIX)) == 0) {
 	 	UDBG;
 	 	printk("skip bkp creation");
 	 	return 0;	
 	 }

 	//Get hidden directory
	lower_parent_dentry = lock_parent(lower_orig_file->f_path.dentry);
	bkp_folder_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
 	err = get_bkp_folder_dentry(lower_parent_dentry, lower_orig_file->f_path.mnt, org_dentry->d_name.name, bkp_folder_dentry_ptr);

 	if (err) {
 		goto out;
 	}
 	bkp_folder_dentry = *bkp_folder_dentry_ptr;

	// Get hidden directory attribute
	dentry_meta_data = kmalloc(sizeof(struct lower_dentry_meta_data), GFP_KERNEL);
	err = vfs_getxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data));
	if (err < 0) {
		printk("Xattr Null");
		kfree(dentry_meta_data);
		err = -EINVAL;
		goto out;
	}

	global_meta_data = &BKPFS_SB(org_dentry->d_sb)->global_meta_data;
	if (global_meta_data == NULL) {
		printk("No global bkp meta data.");
		goto free_out;
	}

	file_size = file->f_path.dentry->d_inode->i_size;
	printk("file size %lld", file_size);

	if (file_size == 0) {
		printk("Blank file. Skipping backup.");
		goto out;
	}

	#ifdef EXTRA_CREDIT
		if (file_size > global_meta_data->max_size_kb) {
			printk("File size more than allowed space. Skipping backup.");
			goto out;
		}
	#endif
	
	total_max_backup = global_meta_data->max_backup_version;
	printk("max_verison %d", total_max_backup);

	current_bkp_version = dentry_meta_data->max_version;
	printk("cur max version %d", current_bkp_version);

	max_size = global_meta_data->max_size_kb;
	printk("max size %d", max_size);

	old_size = dentry_meta_data->size_kb;
	printk("cur folder size %d", old_size);

	new_size = old_size;

	// create backup file
	new_bkp_file_name = kmalloc(lenHelper(get_wrapped_name_mk(org_dentry, current_bkp_version) + 1), GFP_KERNEL);
	sprintf(new_bkp_file_name, "%d", get_wrapped_name_mk(org_dentry, current_bkp_version) + 1);

	err = get_dentry(bkp_folder_dentry, new_bkp_file_name, lower_orig_file->f_path.mnt, &new_bkp_file_dentry);
	if (err != -ENOENT) {
		goto out;
	}

	printk("Tryng to create bkp file");
	err = vfs_create(d_inode(bkp_folder_dentry), new_bkp_file_dentry, S_IRWXU, 1);

	if (err) {
		printk("Failed to create bkp file");
		goto out;
	}

	printk("bkp file created");

	UDBG;

	temp_path_out = kmalloc(sizeof(struct path), GFP_KERNEL);
	temp_path_out->mnt = lower_orig_file->f_path.mnt;
	temp_path_out->dentry = new_bkp_file_dentry;
	path_get(temp_path_out);

	UDBG;

	file_out = dentry_open(temp_path_out, O_RDWR, current_cred());
	if (IS_ERR(file_out)) {
		printk("File open failed");
		err = PTR_ERR(file_out);
		goto free_out;
	}

	if (file_out == NULL) {
		printk("file out is null");
		goto free_out;
	} else {
		printk("Bkp file name is %s", file_out->f_path.dentry->d_name.name);
	}

	temp_path_in = kmalloc(sizeof(struct path), GFP_KERNEL);
	temp_path_in->mnt = lower_orig_file->f_path.mnt;
	temp_path_in->dentry = lower_orig_file->f_path.dentry;
	path_get(temp_path_in);

	UDBG;

	file_in_read = dentry_open(temp_path_in, O_RDONLY, current_cred());
	if (IS_ERR(file_in_read)) {
		printk("File open failed");
		err = PTR_ERR(file_in_read);
		goto free_in;
	}

	err = vfs_copy_file_range(file_in_read, pos, file_out, pos2,
			    file_size, 0);
	if (err < 1) {
		printk("File contents not copied");
		delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name_mk(org_dentry, current_bkp_version) + 1);
		goto free_in;
	}

	printk("copy returned %d", err);
	new_size = new_size + file_size;

	fsstack_copy_inode_size(file_inode(file_out),
				file_inode(file_in_read));
	fsstack_copy_attr_times(file_inode(file_out),
				file_inode(file_in_read));

	// // update current version
	if (dentry_meta_data->min_version == 0) {
		dentry_meta_data->min_version = 1;	
	}
	dentry_meta_data->max_version = dentry_meta_data->max_version + 1;

	UDBG;

	// check for delete
	if (dentry_meta_data->max_version <= total_max_backup) {
		printk("old bkp files delete not necessary, by num const");
		goto delete_size;
	}

	tmp_for_delete = dentry_meta_data->max_version - total_max_backup;
	while (tmp_for_delete > 0 && tmp_for_delete >= dentry_meta_data->min_version) {

		printk("check to delete if exists, num constraint, %d", get_wrapped_name(org_dentry, tmp_for_delete));

		err = delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name(org_dentry, tmp_for_delete));
		if (err < 0) {
			printk("Delete failed");
			goto decrement;
		}

		new_size = new_size - err;

	UDBG;
decrement:
		tmp_for_delete = tmp_for_delete - 1;
	}

	dentry_meta_data->min_version = dentry_meta_data->max_version - total_max_backup + 1;

delete_size:

	#ifdef EXTRA_CREDIT
		// EC code here

		tmp_for_delete = dentry_meta_data->min_version;
		temp = 0;
		while (new_size > max_size && tmp_for_delete <= dentry_meta_data->max_version) {

			printk("check to delete if exists, size constraint, %d", get_wrapped_name(org_dentry, tmp_for_delete));

			err = delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name(org_dentry, tmp_for_delete));
			if (err < 0) {
				printk("Delete failed");
				break;
			}

			tmp_for_delete = tmp_for_delete + 1;
			temp = temp + 1;
			new_size = new_size - err;	
		}

		dentry_meta_data->min_version = dentry_meta_data->min_version + temp;
		dentry_meta_data->size_kb = new_size;
		printk("folder size %d", dentry_meta_data->size_kb);

	#endif

	if (dentry_meta_data->max_version > 6 * total_max_backup) {

		temp = dentry_meta_data->max_version - dentry_meta_data->min_version;
		dentry_meta_data->max_version = (dentry_meta_data->max_version%(2 * total_max_backup)) + (2 * total_max_backup);
		dentry_meta_data->min_version = dentry_meta_data->max_version - temp;
	}

	if (dentry_meta_data) {
		err = vfs_setxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data), 0);
		printk("err %d", err);	
		if (!err) {
			printk("Successfuly set xattr");
		}	
	}

free_in:
	if (temp_path_in != NULL) {
		UDBG;
		path_put(temp_path_in);
	}

free_out:
	if (temp_path_out != NULL) {
		UDBG;
		path_put(temp_path_out);
	}

out :

	unlock_dir(lower_parent_dentry);

	if (bkp_folder_dentry_ptr) {
		kfree(bkp_folder_dentry_ptr);
	}

	return err0;
}

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent __user * current_dir;
	struct linux_dirent __user * previous;
	int count;
	int error;
};


static int bkpfs_filldir(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	

	struct linux_dirent __user * dirent;
	struct getdents_callback *buf =
		container_of(ctx, struct getdents_callback, ctx);
	unsigned long d_ino;
	int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + namlen + 2,
		sizeof(long));

	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	dirent = buf->previous;
	if (dirent) {
		if (signal_pending(current))
			return -EINTR;
		if (__put_user(offset, &dirent->d_off))
			goto efault;
	}
	dirent = buf->current_dir;

	if(strncmp(name, BKP_FOLDER_PREFIX, strlen(BKP_FOLDER_PREFIX)) == 0) {
		printk("hide file from ls %s", name);
	 	return 0;
	}

	if (__put_user(d_ino, &dirent->d_ino))
		goto efault;
	if (__put_user(reclen, &dirent->d_reclen))
		goto efault;
	if (copy_to_user(dirent->d_name, name, namlen))
		goto efault;
	if (__put_user(0, dirent->d_name + namlen))
		goto efault;
	if (__put_user(d_type, (char __user *) dirent + reclen - 1))
		goto efault;
	buf->previous = dirent;
	dirent = (void __user *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

static int bkpfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	ctx->actor = bkpfs_filldir;

	lower_file = bkpfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static int parseFromUser(unsigned long arg, struct bkps_ioctl_args *ioctl_args) {

	int ret;
	int err = 0;

	// struct filename *temp;
	
	// Copy data from user. 
	ret = copy_from_user(ioctl_args, (bkps_ioctl_args *)arg, sizeof(bkps_ioctl_args));
	if (ret == 0) {
		printk("Struct copied successfully");
	} else {
		printk("Copy from user failed");
		err = -EFAULT;
		goto out;
	}

	// zero length password
	if (ioctl_args->file_name_length == 0) {
		printk("zero length file name");
		err = -EINVAL;
		goto out;		
	}
	
	// null password hash received
	if (((bkps_ioctl_args *)arg)->file_name == NULL) {
		printk("Null file name");
		err = -EINVAL;
		goto out;
	} 
	
	// Check that kernel can read password hash passed
	if (access_ok(VERIFY_READ, ((bkps_ioctl_args *)arg)->file_name, ioctl_args->file_name_length) == 0) {
		printk("Access check for file name fails");
		err = -EFAULT;
		goto out;
	}

	// Allocate memory to store password hash
	ioctl_args->file_name = (char *)kmalloc(strlen(((bkps_ioctl_args *)arg)->file_name) + 1, GFP_KERNEL);
	if (ioctl_args->file_name == NULL) {
		printk("Failed to allocate memory for file name");
		err = -ENOMEM;
		goto out;
	}

	strcpy(ioctl_args->file_name, ((bkps_ioctl_args *)arg)->file_name);

out :
	//putname(temp);
	return err;

}

int listFiles(bkps_ioctl_args *ioctl_args, struct file *lower_orig_file, char **buf) {

	int ret = 0;

	struct dentry *bkp_folder_dentry;
	struct dentry **bkp_folder_dentry_ptr;

	struct dentry *lower_parent_dentry;

	struct lower_dentry_meta_data *dentry_meta_data = NULL;
	int i = 0;
	int len = 0;
	char *temp;

	lower_parent_dentry = dget_parent(lower_orig_file->f_path.dentry);

	bkp_folder_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
 	ret = get_bkp_folder_dentry(lower_parent_dentry, lower_orig_file->f_path.mnt, ioctl_args->file_name, bkp_folder_dentry_ptr);
 	if (ret != 0) {
 		UDBG;
 		goto out;
 	}
 	bkp_folder_dentry = *bkp_folder_dentry_ptr;

	// Get hidden directory attribute
	dentry_meta_data = kmalloc(sizeof(struct lower_dentry_meta_data), GFP_KERNEL);
	ret = vfs_getxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data));
	if (ret < 0) {
		kfree(dentry_meta_data);
		printk("Xattr Null");
		ret = -EINVAL;
		goto out;
	}

	temp = kmalloc(lenHelper(dentry_meta_data->max_version), GFP_KERNEL);
	strcpy(temp, "");

	i = dentry_meta_data->max_version;
	while (i >= dentry_meta_data->min_version && i > 0) {

		sprintf(temp, "%d", i);

		if (len + strlen(temp) + 2 > PAGE_SIZE) 
			break;

		strcat(*buf, temp);
		len = len + strlen(temp);

		if (i > 1 && i > dentry_meta_data->min_version) {
			strcat(*buf, ", ");		
			len = len + 2;
		}

		i = i - 1;
	}

	if (len == 0) {
		ret = -EINVAL;
	} else {
		ret = len;
	}

	UDBG;

out :
	if (temp)
		kfree(temp);

	if (dentry_meta_data)
		kfree(dentry_meta_data);

	printk("list files return %d", ret);

	return ret;

}

int deleteVersion(struct file *lower_orig_file, char *file_name, int bkp_file_version, struct file *org_file) {

	int ret = 0;
	int err = 0;
	int f;

	struct dentry *lower_parent_dentry;

	struct dentry *bkp_folder_dentry;
	struct dentry **bkp_folder_dentry_ptr;

	struct lower_dentry_meta_data *dentry_meta_data;

	lower_parent_dentry = lock_parent(lower_orig_file->f_path.dentry);

	if (bkp_file_version != FILE_LATEST &&
		bkp_file_version != FILE_OLDEST &&
		bkp_file_version != FILE_ALL) {
		UDBG;
		ret = -EINVAL;
		goto out;
	}

	bkp_folder_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
 	ret = get_bkp_folder_dentry(lower_parent_dentry, lower_orig_file->f_path.mnt, file_name, bkp_folder_dentry_ptr);
 	if (ret) {
 		goto out;
 	}

 	UDBG;
 	bkp_folder_dentry = *bkp_folder_dentry_ptr;

 	dentry_meta_data = kmalloc(sizeof(struct lower_dentry_meta_data), GFP_KERNEL);
	ret = vfs_getxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data));
	if (ret < 0) {
		UDBG;
		printk("Xattr Null");
		kfree(dentry_meta_data);
		ret = -EINVAL;
		goto out;
	}
	UDBG;


	if (bkp_file_version == FILE_LATEST) {

		if (dentry_meta_data->max_version <=0 || dentry_meta_data->max_version < dentry_meta_data->min_version) {
			ret = -EINVAL;
			goto out;
		}

		ret = delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name(org_file->f_path.dentry, dentry_meta_data->max_version));
		if (ret <= 0) {
			printk("Delete failed");
			goto out;
		}

		if (ret > 0) {
			dentry_meta_data->size_kb = dentry_meta_data->size_kb - ret;
			dentry_meta_data->max_version = dentry_meta_data->max_version - 1;
			UDBG;

			if (dentry_meta_data->min_version > dentry_meta_data->max_version) {
				dentry_meta_data->min_version = 0;
				dentry_meta_data->max_version = 0;
				dentry_meta_data->size_kb = 0;
			}

			err = vfs_setxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data), 0);
			printk("err %d", err);	
			if (!err) {
				printk("Successfuly set xattr");
			}
		}
	
	}

	if (bkp_file_version == FILE_OLDEST) {

		if (dentry_meta_data->min_version <= 0 || dentry_meta_data->max_version < dentry_meta_data->min_version) {
			ret = -EINVAL;
			goto out;
		}

		ret = delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name(org_file->f_path.dentry, dentry_meta_data->min_version));
		if (ret <= 0) {
			printk("Delete failed");
			goto out;
		}

		if (ret > 0) {
			UDBG;
			dentry_meta_data->size_kb = dentry_meta_data->size_kb - ret;
			dentry_meta_data->min_version = dentry_meta_data->min_version + 1;

			if (dentry_meta_data->min_version > dentry_meta_data->max_version) {
				dentry_meta_data->min_version = 0;
				dentry_meta_data->max_version = 0;
				dentry_meta_data->size_kb = 0;
			}

			err = vfs_setxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data), 0);
			printk("err %d", err);	
			if (!err) {
				printk("Successfuly set xattr");
			}
		}
	
	}

	if (bkp_file_version == FILE_ALL) {

		if (dentry_meta_data->max_version < dentry_meta_data->min_version) {
			ret = -EINVAL;
			goto out;
		}

		f = dentry_meta_data->max_version;

		while (f >= dentry_meta_data->min_version) {

			err = delete_dentry(bkp_folder_dentry, lower_orig_file->f_path.mnt, get_wrapped_name(org_file->f_path.dentry, f));
			if (err <= 0) {
				printk("Delete failed");
				goto out_all;
			}

			if (err > 0) {
				dentry_meta_data->size_kb = dentry_meta_data->size_kb - err;
				dentry_meta_data->max_version = dentry_meta_data->max_version - 1;
			}
		
			f = f - 1;
		}

	out_all :
		if (dentry_meta_data->min_version > dentry_meta_data->max_version) {
			dentry_meta_data->min_version = 0;
			dentry_meta_data->max_version = 0;
			dentry_meta_data->size_kb = 0;
		}

		err = vfs_setxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data), 0);
		printk("err %d", err);	
		if (!err) {
			printk("Successfuly set xattr");
		}

	}

out :
	unlock_dir(lower_parent_dentry);
	return ret;

}

int restoreVersion(bkps_ioctl_args *ioctl_args, struct file *lower_orig_file, struct file *org_file) {

	int ret;
	struct dentry *bkp_folder_dentry;
	struct dentry **bkp_folder_dentry_ptr;

	struct dentry *res_bkp_file_dentry;

	struct dentry *orig_file_dentry;

	struct dentry *lower_parent_dentry;
	struct lower_dentry_meta_data *dentry_meta_data = NULL;

	char* filename_to_restore;

	loff_t pos = 0;
	loff_t pos2 = 0;
	struct file *file_in_read;
	struct path *temp_path_in;
	struct file *file_out;
	struct path *temp_path_out;
	loff_t file_size;

	lower_parent_dentry = lock_parent(lower_orig_file->f_path.dentry);
	UDBG;

	bkp_folder_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
 	ret = get_bkp_folder_dentry(lower_parent_dentry, lower_orig_file->f_path.mnt, ioctl_args->file_name, bkp_folder_dentry_ptr);
 	if (ret) {
 		goto out;
 	}

	UDBG;
 	bkp_folder_dentry = *bkp_folder_dentry_ptr;

	dentry_meta_data = kmalloc(sizeof(struct lower_dentry_meta_data), GFP_KERNEL);
	ret = vfs_getxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data));
	if (ret < 0) {
		UDBG;
		printk("Xattr Null");
		kfree(dentry_meta_data);
		ret = -EINVAL;
		goto out;
	}
	UDBG;

 	if (ioctl_args->bkp_file_version < dentry_meta_data->min_version) {
 		ret = -EINVAL;
 		goto out;
 	}
 	UDBG;
 	if (ioctl_args->bkp_file_version > dentry_meta_data->max_version) {
 		ret = -EINVAL;
 		goto out;
 	}
 	UDBG;

	filename_to_restore = kmalloc(lenHelper(get_wrapped_name(org_file->f_path.dentry, ioctl_args->bkp_file_version)), GFP_KERNEL);
	sprintf(filename_to_restore, "%d", get_wrapped_name(org_file->f_path.dentry, ioctl_args->bkp_file_version));
	printk("get version to restore %s", filename_to_restore);

	UDBG;

	ret = get_dentry(bkp_folder_dentry, filename_to_restore, lower_orig_file->f_path.mnt, &res_bkp_file_dentry);
	if (ret) {
		printk("Bkp file could not be located");
		goto out;
	}

	ret = get_dentry(lower_parent_dentry, ioctl_args->file_name, lower_orig_file->f_path.mnt, &orig_file_dentry);
	if (ret) {
		printk("Orig file could not be located");
		goto out;
	}

	printk("Restore now");

	temp_path_in = kmalloc(sizeof(struct path), GFP_KERNEL);
	temp_path_in->mnt = lower_orig_file->f_path.mnt;
	temp_path_in->dentry = res_bkp_file_dentry;
	path_get(temp_path_in);

	UDBG;

	file_in_read = dentry_open(temp_path_in, O_RDONLY, current_cred());
	if (IS_ERR(file_in_read)) {
		printk(" BKP file open failed");
		ret = PTR_ERR(file_in_read);
		goto free_in;
	}

	UDBG;

	temp_path_out = kmalloc(sizeof(struct path), GFP_KERNEL);
	temp_path_out->mnt = lower_orig_file->f_path.mnt;
	temp_path_out->dentry = orig_file_dentry;
	path_get(temp_path_out);

	UDBG;

	file_out = dentry_open(temp_path_out, O_RDWR | O_TRUNC, current_cred());
	if (IS_ERR(file_out)) {
		printk("Orig file open failed");
		ret = PTR_ERR(file_out);
		goto free_out;
	}

	file_size = MAX(file_in_read->f_path.dentry->d_inode->i_size, file_out->f_path.dentry->d_inode->i_size);
	printk("file size %lld", file_size);

	ret = vfs_copy_file_range(file_in_read, pos, file_out, pos2,
			    file_size, 0);
	if (ret < 1) {
		printk("File contents not copied");
		goto free_out;
	}

	fsstack_copy_inode_size(file_inode(file_out),
				file_inode(file_in_read));
	fsstack_copy_attr_times(file_inode(file_out),
				file_inode(file_in_read));

	printk("copy returned %d", ret);

free_out:
	if (temp_path_out != NULL) {
		UDBG;
		path_put(temp_path_out);
	}

free_in:
	if (temp_path_in != NULL) {
		UDBG;
		path_put(temp_path_in);
	}

out :

	unlock_dir(lower_parent_dentry);

	if (dentry_meta_data)
		kfree(dentry_meta_data);

	return ret;

}

int readVersion(bkps_ioctl_args *ioctl_args, struct file *lower_orig_file, char** buf, struct file *org_file) {

	int err = 0;
	int ret = 0;
	
	struct dentry *bkp_folder_dentry;
	struct dentry **bkp_folder_dentry_ptr;

	struct dentry *lower_parent_dentry;

	struct dentry *view_bkp_file_dentry;
	struct lower_dentry_meta_data *dentry_meta_data; 

	struct path *temp_path_in;
	struct file *file_in_read; 
	loff_t pos = 0;
	loff_t len_to_read = 0;

	char* filename_to_view;
	mm_segment_t oldfs;

	lower_parent_dentry = lock_parent(lower_orig_file->f_path.dentry);

 	bkp_folder_dentry_ptr = kmalloc(sizeof(struct dentry *), GFP_KERNEL);
 	err = get_bkp_folder_dentry(lower_parent_dentry, lower_orig_file->f_path.mnt, ioctl_args->file_name, bkp_folder_dentry_ptr);
 	if (err) {
 		UDBG;
 		goto out;
 	}

	UDBG;

 	bkp_folder_dentry = *bkp_folder_dentry_ptr;

	dentry_meta_data = kmalloc(sizeof(struct lower_dentry_meta_data), GFP_KERNEL);
	err = vfs_getxattr(bkp_folder_dentry, BKP_ATTRIBUTE_KEY, dentry_meta_data, sizeof(struct lower_dentry_meta_data));
	if (err < 0) {
		printk("Xattr Null");
		kfree(dentry_meta_data);
		err = -EINVAL;
		goto out;
	}

	UDBG;

 	if (ioctl_args->bkp_file_version < dentry_meta_data->min_version) {
 		err = -EINVAL;
 		goto out;
 	}

 	if (ioctl_args->bkp_file_version > dentry_meta_data->max_version) {
 		err = -EINVAL;
 		goto out;
 	}

 	UDBG;

	filename_to_view = kmalloc(lenHelper(get_wrapped_name(org_file->f_path.dentry, ioctl_args->bkp_file_version)), GFP_KERNEL);
	sprintf(filename_to_view, "%d", get_wrapped_name(org_file->f_path.dentry, ioctl_args->bkp_file_version));
	printk("get version to view %s", filename_to_view);

	UDBG;

	err = get_dentry(bkp_folder_dentry, filename_to_view, lower_orig_file->f_path.mnt, &view_bkp_file_dentry);
	if (err) {
		goto out;
	}

	UDBG;

	temp_path_in = kmalloc(sizeof(struct path), GFP_KERNEL);
	temp_path_in->mnt = lower_orig_file->f_path.mnt;
	temp_path_in->dentry = view_bkp_file_dentry;
	path_get(temp_path_in);

	UDBG;

	file_in_read = dentry_open(temp_path_in, O_RDONLY, current_cred());
	if (IS_ERR(file_in_read)) {
		printk(" BKP file open failed");
		err = PTR_ERR(file_in_read);
		goto free_path;
	}

	UDBG;

	pos = ioctl_args->read_offset;
	len_to_read = MIN(file_in_read->f_path.dentry->d_inode->i_size - pos , PAGE_SIZE);
	
	printk("length to read %lld", len_to_read);

	*buf = kmalloc(len_to_read, GFP_KERNEL);
	UDBG;

	oldfs = get_fs();
    set_fs(KERNEL_DS);
	ret = vfs_read(file_in_read, *buf, len_to_read, &pos);
	set_fs(oldfs);

	if (ret > 0) {
		err = ret;
	}

free_path :
	
	if (temp_path_in)
		path_put(temp_path_in);

out:

	unlock_dir(lower_parent_dentry);

	return err;
}

static long bkpfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	int err = 0;
	int ret;
	struct file *lower_file;
	struct bkps_ioctl_args *ioctl_args = NULL;
	// struct dentry *bkp_directory;
	char **buf;
	struct list_head **list;

	// struct bkp_file_list_entry_user *ptr_user;
	char *temp_bkp_files_list;
	// char *temp;

	// int ctr = 0;
	// int len = 0;

	lower_file = bkpfs_lower_file(file);
	
	list = kmalloc(sizeof(struct list_head *), GFP_KERNEL);

	if (cmd == IOCTL_LIST_VERSIONS ||
		cmd == IOCTL_VIEW_VERSION ||
		cmd == IOCTL_DELETE_VERSION ||
		cmd == IOCTL_RESTORE_VERSION) {

		if (((bkps_ioctl_args *)arg) == NULL) {
			printk("Null paramter received");
			err = -EINVAL;
			goto out;
		}

		// Verify that kernel can read user address passed
		if (access_ok(VERIFY_READ, (bkps_ioctl_args *)arg, sizeof(struct bkps_ioctl_args)) == 0) {
			printk("Access check fails");
			err = -EACCES;
			goto out;
		}
		
		// Allocate memory to copy data from user in to.
		ioctl_args = (bkps_ioctl_args *)kmalloc(sizeof(bkps_ioctl_args), GFP_KERNEL);
		if (ioctl_args == NULL) {
			printk("Failed to allocate memory for struct");
			err = -ENOMEM;
			goto out;
		}
		memset(ioctl_args, 0, sizeof(bkps_ioctl_args));

		UDBG;

		switch (cmd) {
			case IOCTL_LIST_VERSIONS: 
				printk("list all versions");
				ret = parseFromUser(arg, ioctl_args);
				if (ret != 0) {
					printk("ret %d", ret);
					UDBG;
					err = ret;
					goto out;
				}
				printk("after parse file_name %s", ioctl_args->file_name);

				UDBG;

				temp_bkp_files_list = kmalloc(PAGE_SIZE, GFP_KERNEL);
				strcpy(temp_bkp_files_list, "");
				ret = listFiles(ioctl_args, lower_file, &temp_bkp_files_list);

				if (ret < 0) {
					kfree(temp_bkp_files_list);
					goto out;	
				}

				if (ret == 0) {
					kfree(temp_bkp_files_list);
					ret = -EINVAL;
					goto out;
				}


				printk("final string %s", temp_bkp_files_list);
				printk("final string r %d", ret);

				UDBG;

				if (access_ok(VERIFY_WRITE, ioctl_args->bkp_files_view, PAGE_SIZE) == 0) {
					printk("Access check fails");
					ret = -EACCES;
					goto out;
				}

				err = copy_to_user(ioctl_args->bkp_files_view, temp_bkp_files_list, ret);

				if (!err) {
					kfree(temp_bkp_files_list);
					goto out;
				}

				if (err < 0) {
					printk("%d", err);
					printk("Copy to user failed");
					kfree(temp_bkp_files_list);
					ret = -EFAULT;
				}

				goto out;

			case IOCTL_VIEW_VERSION: 
				ret = parseFromUser(arg, ioctl_args);
				if (ret != 0) {
					printk("ret %d", ret);
					UDBG;
					err = ret;
					goto out;
				}
				printk("after parse file_name %s", ioctl_args->file_name);

				buf = kmalloc(sizeof(char *), GFP_KERNEL);
				ret = readVersion(ioctl_args, lower_file, buf, file);
				if (ret < 1) {
					kfree(*buf);
					kfree(buf);
					goto out;
				}
				printk("after read %d", ret);

				if (access_ok(VERIFY_WRITE, ((bkps_ioctl_args *)arg)->buf, PAGE_SIZE) == 0) {
					printk("Access check fails");
					ret = -EACCES;
					goto out;
				}

				printk("after read %d", ret);

				err = copy_to_user(ioctl_args->buf, *buf, ret);

				if (!err) {
					kfree(*buf);
					kfree(buf);
					goto out;
				}

				if (err < 0) {
					printk("Copy to user failed");
					ret = -EFAULT;
					kfree(*buf);
					kfree(buf);
				}
				goto out;

			case IOCTL_DELETE_VERSION: 
				printk("delete version");
				err = parseFromUser(arg, ioctl_args);
				printk("after parse file_name %s", ioctl_args->file_name);
				printk("after parse file_version %d", ioctl_args->bkp_file_version);

				ret = deleteVersion(lower_file, ioctl_args->file_name, ioctl_args->bkp_file_version, file);
				if (ret > 0) {
					ret = 0;
				}
				goto out;
			case IOCTL_RESTORE_VERSION:
				printk("restore version");
				err = parseFromUser(arg, ioctl_args);
				if (ret != 0) {
					printk("ret %d", ret);
					UDBG;
					err = ret;
					goto out;
				}
				// printk("after parse file_name %s", ioctl_args->file_name);
				// printk("after parse file_version %d", ioctl_args->bkp_file_version);
				ret = restoreVersion(ioctl_args, lower_file, file);
				if (ret > 0) {
					ret = 0;
				}
				goto out;
		}

	}

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	printk("Returned %d\n", ret);
	return ret;
}

#ifdef CONFIG_COMPAT
static long bkpfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = bkpfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int bkpfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = bkpfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "bkpfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!BKPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "bkpfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &bkpfs_vm_ops;

	file->f_mapping->a_ops = &bkpfs_aops; /* set our aops */
	if (!BKPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		BKPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int bkpfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct bkpfs_file_info), GFP_KERNEL);
	if (!BKPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link bkpfs's file struct to lower's */
	bkpfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = bkpfs_lower_file(file);
		if (lower_file) {
			bkpfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		bkpfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(BKPFS_F(file));
	else
		fsstack_copy_attr_all(inode, bkpfs_lower_inode(inode));
out_err:
	return err;
}

static int bkpfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = bkpfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int bkpfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (lower_file) {
		bkpfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(BKPFS_F(file));
	return 0;
}

static int bkpfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = bkpfs_lower_file(file);
	bkpfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	bkpfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int bkpfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = bkpfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * BKPfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t bkpfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = bkpfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * BKPfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
bkpfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * BKPfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
bkpfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations bkpfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= bkpfs_read,
	.write		= bkpfs_write,
	.unlocked_ioctl	= bkpfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bkpfs_compat_ioctl,
#endif
	.mmap		= bkpfs_mmap,
	.open		= bkpfs_open,
	.flush		= bkpfs_flush,
	.release	= bkpfs_file_release,
	.fsync		= bkpfs_fsync,
	.fasync		= bkpfs_fasync,
	.read_iter	= bkpfs_read_iter,
	.write_iter	= bkpfs_write_iter,
};

/* trimmed directory options */
const struct file_operations bkpfs_dir_fops = {
	.llseek		= bkpfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= bkpfs_readdir,
	.unlocked_ioctl	= bkpfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bkpfs_compat_ioctl,
#endif
	.open		= bkpfs_open,
	.release	= bkpfs_file_release,
	.flush		= bkpfs_flush,
	.fsync		= bkpfs_fsync,
	.fasync		= bkpfs_fasync,
};

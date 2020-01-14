// SPDX-License-Identifier: GPL-2.0+
// Some of the code on this file has been
// referred from www.kernel.org
#include <linux/linkage.h>

#include <linux/moduleloader.h>

#include<linux/slab.h>

#include <linux/uaccess.h>

#include <asm/uaccess.h>

#include "e_struct.h"

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

asmlinkage extern long( * sysptr)(void * arg);

#define MD5_BYTE_SIZE 16# define AES_KEY_SIZE 16

/////////////// HASH ////////////
/*
 *struct object to store data related to hashing.
 */
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

/*
 *
 *Initialize hash object in to struct.
 */
static struct sdesc * init_sdesc(struct crypto_shash * alg) {
    struct sdesc * sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc - > shash.tfm = alg;
    sdesc - > shash.flags = 0x0;
    return sdesc;
}

/**
 *
 *Compute hash provided an initialized crypto_shash object,
 *input data string, length of string and a conatiner to store
 *the hash - digest.
 */
static int hash_internal(struct crypto_shash * alg,
    const unsigned char * data, unsigned int datalen, unsigned char * digest) {
    struct sdesc * sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest( & sdesc - > shash, data, datalen, digest);
    return ret;
}

/**
 *Method to be called by main program. Allocates crypto_shash object,
 *generates object and frees object afterwords.
 *data - input string, len - length of input string,
 *result - container for hash generated.
 */
static int md5_hash(char * result, char * data, int len) {
    struct crypto_shash * alg;
    char * hash_alg_name = "md5";
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = hash_internal(alg, data, len, result);
    crypto_free_shash(alg);
    return ret;
}

////////////  Encryption/Decryption /////////

/**
 *struct defined to hold encryption objects
 */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher * tfm;
    struct skcipher_request * req;
    struct crypto_wait wait;
}
skcipher_def;

/**
 *Method to initialize cipher objects for encryption/decryption for AES 128.
 *encryption_key - 16 bit string for key.
 *ivdata - 16 bit string as IV.
 */
static int init_ctr_aes(struct skcipher_def * sk, unsigned char * encryption_key,
    char * ivdata) {
    struct crypto_skcipher * skcipher = NULL;
    struct skcipher_request * req = NULL;
    int ret = 0;

    pr_debug("init cipher\n");

    skcipher = crypto_alloc_skcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(skcipher)) {
        pr_debug("could not allocate skcipher handle\n");
        ret = PTR_ERR(skcipher);
        goto out;
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_debug("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
        crypto_req_done, &
        sk - > wait);

    if (crypto_skcipher_setkey(skcipher, encryption_key, 16)) {
        pr_debug("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    sk - > tfm = skcipher;
    sk - > req = req;

    out:
        pr_debug("init cipher done");
    return ret;
}

/**
 *
 *Method to perform encryption.
 *plain text data is in buffer.
 *ivdata has iv.
 *len is the length of string to encrypt from buffer.
 *Encrypted text is written in to buf.
 */
static int encrpyt(struct skcipher_def * sk, char * ivdata, char * buf,
    unsigned int len) {
    int rc;

    pr_debug("encrypt");

    if (sk - > req == NULL) {
        pr_debug("null sk");
        rc = -EINVAL;
    }

    if ( & sk - > sg == NULL) {
        pr_debug("null sg");
        rc = -EINVAL;
    }

    if (ivdata == NULL) {
        pr_debug("null iv");
        rc = -EINVAL;
    }

    sg_init_one( & sk - > sg, buf, len);
    skcipher_request_set_crypt(sk - > req, & sk - > sg, & sk - > sg, len, ivdata);
    crypto_init_wait( & sk - > wait);

    rc = crypto_wait_req(crypto_skcipher_encrypt(sk - > req), & sk - > wait);

    return rc;
}

/**
 *
 *Method to perform decryption.
 *encrypted text data is in buffer.
 *ivdata has iv.
 *len is the length of string to encrypt from buffer.
 *Plain text is written in to buf.
 */
static int decrypt(struct skcipher_def * sk, char * ivdata, char * buf,
    unsigned int len) {
    int rc;

    pr_debug("decrypt");

    if (sk - > req == NULL) {
        pr_debug("null sk");
        return -EINVAL;
    }

    if ( & sk - > sg == NULL) {
        pr_debug("null sg");
        return -EINVAL;
    }

    if (ivdata == NULL) {
        pr_debug("null iv");
        return -EINVAL;
    }

    sg_init_one( & sk - > sg, buf, len);
    skcipher_request_set_crypt(sk - > req, & sk - > sg, & sk - > sg, len, ivdata);
    crypto_init_wait( & sk - > wait);

    rc = crypto_wait_req(crypto_skcipher_decrypt(sk - > req), & sk - > wait);

    return rc;
}

/**
 *
 *This method is used when copying data without encryption/decryption.
 *Since copy just copies contents with no change, the method does nothing.
 *
 */
static int do_nothing(struct skcipher_def * sk, char * ivdata, char * buf,
    unsigned int len) {
    pr_debug("do nothing");
    return 0;
}

/////////////////// File Operations ///////////
/**
 *Read file filp*, starting from offset to length len.
 *Store result in buf
 */
int read_file(struct file * filp, void * buf, int len, int offset) {
    mm_segment_t oldfs;
    int ret;

    filp - > f_pos = offset;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = vfs_read(filp, buf, len, & filp - > f_pos);
    set_fs(oldfs);
    return ret;
}

/**
 *Write file filp*, starting from offset to length len.
 *Data to write is in buf.
 */
int file_write(struct file * filp, void * buf, int len, int offset) {

    mm_segment_t oldfs;
    int ret;

    ret = 0;
    oldfs = get_fs();
    set_fs(KERNEL_DS);

    filp - > f_pos = offset;

    ret = vfs_write(filp, buf, len, & filp - > f_pos);

    set_fs(oldfs);
    return ret;
}

/**
 *Method to check if right password is provided to decrypt the file.
 *When file is encrypted, the double hash of the password is stored at beginning.
 *When decrypting, we double hash the password provided then and compare to file.
 *digest - double hash of password provided with decryption.
 *file - file to decrypt.
 *len - number of bytes of file data to use for comparison.
 */
static bool checkPassword(unsigned char * digest, struct file * file, int len) {
    unsigned char * buf;
    int rc;
    bool ret = true;

    pr_debug("checking access");

    buf = kmalloc(MD5_BYTE_SIZE, GFP_KERNEL);

    rc = read_file(file, buf, MD5_BYTE_SIZE, 0);
    pr_debug("ret %d", rc);

    if (strncmp(digest, buf, MD5_BYTE_SIZE) != 0)
        ret = false;

    return ret;
}

/**
 *Main method that
 *1) reads data from input file in to buffer of PAGE_SIZE
 *2) transforms data if necessary
 *3) Writes data to output file
 *
 *Param 1 is the function to trandorm data.
 *sk - cipher struct object post initialization.
 *ivdata - iv for encryption.
 *source_file - file to read from.
 *dest_file - file to write to.
 *read_offset - number of bytes to skip in input file while reading.
 *write_offset - number of bytes to skip in output while writing.
 */
static int copyData(int( * transform)(struct skcipher_def * sk, char * ivdata,
        char * ibuf, unsigned int len), struct skcipher_def * sk, char * ivdata,
    struct file * source_file, struct file * dest_file, int read_offset,
    int write_offset) {

    int file_size;
    int bytes_to_read;
    char * buf;
    int rc;
    int ret = 0;

    int read_start;
    int write_start;

    pr_debug("write data");

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    memset(buf, 0x00, PAGE_SIZE);

    read_start = read_offset;
    write_start = write_offset;

    file_size = source_file - > f_inode - > i_size;
    pr_debug("total file size %d\n", file_size);

    if (file_size > 0) {
        do {

            bytes_to_read = ((file_size - read_start) < PAGE_SIZE ?
                (file_size - read_start) : PAGE_SIZE);
            rc = read_file(source_file, buf, bytes_to_read, read_start);
            if (rc < bytes_to_read) {
                pr_debug("Error when reading");
                ret = -EAGAIN;
                goto out;
            }
            pr_debug("bytes read %d\n", rc);

            ( * transform)(sk, ivdata, buf, bytes_to_read);
            rc = file_write(dest_file, buf, bytes_to_read, write_start);
            if (rc < bytes_to_read) {
                pr_debug("Error when writing");
                ret = -EAGAIN;
                goto out;
            }
            pr_debug("bytes written %d\n", rc);
            read_start += bytes_to_read;
            write_start += bytes_to_read;

        } while (read_start < file_size);
    }

    if (dest_file == NULL) {
        ret = -EINVAL;
        goto out;
    }

    out:
        return ret;
}

asmlinkage long cpenc(void * arg) {
    // Custom struct received from user program
    E_Struct * e_struct = NULL;

    // variable to store return values.
    int rc = 0;

    // variable to store operation to perform (e/c/d)
    int flag_operation_requested = 0;

    // Objects to use with getname
    struct filename * file_in = NULL;
    struct filename * file_out = NULL;

    // Pointer to struct to be used for encryption/decryption.
    struct skcipher_def * sk = NULL;

    // Hash of the keybuf received from user space (2nd hash of user password).
    // It is appended at begiining of file.
    unsigned char * preamble = NULL;

    //Objects to store files after opened successfully.
    struct file * file_in_p = NULL;
    struct file * file_out_p = NULL;

    // ret value of this method
    int ret = 0;

    // IV object
    char * ivdata = NULL;

    // dummy object to use with vfs_unlink
    struct inode ** delegated_inode = NULL;

    // variable to check if password is right
    bool pass;

    // utility object for loops.
    int i;

    // Check if we created file. Delete if operation fails.
    bool was_file_created = false;

    // Null arguments.
    if (arg == NULL) {
        pr_debug("Null paramter");
        ret = -EINVAL;
        goto out;
    }

    // Verify that kernel can read user address passed
    if (access_ok(VERIFY_READ, arg, sizeof(struct E_Struct)) == 0) {
        pr_debug("Access check fails");
        ret = -EACCES;
        goto out;
    }

    // Allocate memory to copy data from user in to.
    e_struct = kmalloc(sizeof(E_Struct), GFP_KERNEL);
    memset(e_struct, 0, sizeof(E_Struct));

    // Copy data from user.
    rc = copy_from_user((E_Struct * ) e_struct, arg, sizeof(E_Struct));
    if (rc == 0) {
        pr_debug("Struct copied successfully");
    } else {
        pr_debug("Copy from user failed");
        ret = -ENOMEM;
        goto out;
    }

    // Check if unsuported operation
    flag_operation_requested = e_struct - > flags;
    if (flag_operation_requested != 1 && flag_operation_requested != 2 &&
        flag_operation_requested != 4) {
        pr_debug("Invalid operation flag");
        ret = -EINVAL;
        goto out;
    }

    // If its a copy operation, skip reading password from struct passed
    if (flag_operation_requested == 4)
        goto files;

    // zero length password
    if (e_struct - > keylen == 0) {
        pr_debug("zero length password");
        ret = -EINVAL;
        goto out;
    }

    // null password hash received
    if (((E_Struct * ) arg) - > keybuf == NULL) {
        pr_debug("Null password");
        ret = -EINVAL;
        goto out;
    }

    // Check that kernel can read password hash passed
    if (access_ok(VERIFY_READ, ((E_Struct * ) arg) - > keybuf,
            e_struct - > keylen) == 0) {
        pr_debug("Access check for password fails");
        ret = -EACCES;
        goto out;
    }

    // Allocate memory to store password hash
    e_struct - > keybuf = kmalloc(e_struct - > keylen + 1, GFP_KERNEL);

    // Copy password hash from user memory to kernel memory.
    strncpy(e_struct - > keybuf, ((E_Struct * ) arg) - > keybuf, e_struct - > keylen);
    if (rc == 0) {
        pr_debug("password copied successfully");
    } else {
        pr_debug("Copy password failed");
        ret = -EACCES;
        goto out;
    }

    pr_debug("Password is :%s\n", (char * ) e_struct - > keybuf);
    pr_debug("Password len is :%d\n", e_struct - > keylen);

    files:
        // In file & Out file
        // Null out file
        if (((E_Struct * ) arg) - > outfile == NULL) {
            pr_debug("Out file paramter is null");
            ret = -EINVAL;
            goto out;
        }

    // Null in file
    if (((E_Struct * ) arg) - > infile == NULL) {
        pr_debug("In file paramter is null");
        ret = -EINVAL;
        goto out;
    }

    // Remove errors in input filename with getname
    file_in = getname(((E_Struct * ) arg) - > infile);
    if (IS_ERR(file_in)) {
        ret = PTR_ERR(file_in);
        goto out;
    }

    // Copy name of in file in to kernel memory
    e_struct - > infile = kmalloc(strlen(file_in - > name) + 1, GFP_KERNEL);
    strcpy(e_struct - > infile, file_in - > name);
    putname(file_in);

    // Remove errors in output filename with getname
    file_out = getname(((E_Struct * ) arg) - > outfile);
    if (IS_ERR(file_out)) {
        ret = PTR_ERR(file_out);
        goto out;
    }

    // Copy name of out file in to kernel memory
    e_struct - > outfile = kmalloc(strlen(file_out - > name) + 1, GFP_KERNEL);
    strcpy(e_struct - > outfile, file_out - > name);
    putname(file_out);

    pr_debug("In file %s\n", e_struct - > infile);
    pr_debug("Out file %s\n", e_struct - > outfile);

    pr_debug("Flags %d\n", e_struct - > flags);
    pr_debug("length %d\n", e_struct - > keylen);

    // Open input file with read only mode.
    file_in_p = filp_open(e_struct - > infile, O_RDONLY, 0);
    if (!file_in_p || IS_ERR(file_in_p)) {
        pr_debug("wrapfs_read_file err %d\n", (int) PTR_ERR(file_in_p));
        ret = PTR_ERR(file_in_p);
        goto out;
    }

    // Open output file with read-write mode. Create if not found.
    file_out_p = filp_open(e_struct - > outfile, O_RDWR, file_in_p - > f_inode - > i_mode);
    if (!file_out_p || IS_ERR(file_out_p)) {

        file_out_p = filp_open(e_struct - > outfile, O_RDWR | O_CREAT,
            file_in_p - > f_inode - > i_mode);
        if (!file_out_p || IS_ERR(file_out_p)) {
            pr_debug("wrapfs_read_file err %d\n", (int) PTR_ERR(file_out_p));
            ret = PTR_ERR(file_out_p);
            goto out;
        } else {
            pr_debug("Created file");
            was_file_created = true;
        }
    }

    // check if input and out are the same file.
    if (file_in_p - > f_inode - > i_ino == file_out_p - > f_inode - > i_ino) {
        pr_debug("Same file");
        ret = -EINVAL;
        goto out;
    }

    // If copy, skip creating preamble (file/header)
    if (flag_operation_requested == 4)
        goto operations;

    preamble = kmalloc(MD5_BYTE_SIZE, GFP_KERNEL);
    memset(preamble, 0x00, MD5_BYTE_SIZE);
    rc = md5_hash(preamble, e_struct - > keybuf, e_struct - > keylen);
    if (rc != 0) {
        ret = rc;
        goto out;
    }

    if (strlen(preamble) == 0) {
        pr_debug("Failed to generate preamble");
        ret = -EINVAL;
        goto out;
    }
    for (i = 0; i < 16; i++)
        pr_debug("preamble %02x", *(preamble + i));

    operations:
        if (flag_operation_requested == 1) { // Encryption mode

            // write preamble
            rc = file_write(file_out_p, preamble, MD5_BYTE_SIZE, 0);

            if (rc < 0) {
                pr_debug("Failed to write preamble");
                ret = -EINVAL;
                goto out;
            }

            ivdata = kmalloc(AES_KEY_SIZE, GFP_KERNEL);

            // fixed IV.
            memset(ivdata, 0x06, 16);

            // Allocate memory for cipher struct
            sk = kmalloc(sizeof(skcipher_def), GFP_KERNEL);
            memset(sk, 0, sizeof(skcipher_def));

            // Initialize cipher strcut
            rc = init_ctr_aes(sk, e_struct - > keybuf, ivdata);
            if (rc < 0) {
                pr_debug("Cipher initialization failed");
                ret = -EINVAL;
                goto out;
            }
            // read, transform and write data.
            rc = copyData(encrpyt, sk, ivdata, file_in_p, file_out_p,
                0, MD5_BYTE_SIZE);
            if (rc < 0) {
                // delete file since copy failed
                if (was_file_created)
                    vfs_unlink(
                        file_out_p - > f_path.dentry - > d_parent - > d_inode,
                        file_out_p - > f_path.dentry, delegated_inode);
                ret = -ENOMEM;
                goto out;
            }
        } else if (flag_operation_requested == 2) { // Decryption mode

        // Check input file header to determine if password is right.
        pass = checkPassword(preamble, file_in_p, MD5_BYTE_SIZE);
        if (pass) {
            pr_debug("access granted");

            // Initialize IV
            ivdata = kmalloc(AES_KEY_SIZE, GFP_KERNEL);

            // fixed IV
            memset(ivdata, 0x06, 16);

            // Allocate memory for cipher struct
            sk = kmalloc(sizeof(skcipher_def), GFP_KERNEL);
            memset(sk, 0, sizeof(skcipher_def));

            rc = init_ctr_aes(sk, e_struct - > keybuf, ivdata);
            if (rc < 0) {
                pr_debug("Cipher initialization failed");
                ret = -EINVAL;
                goto out;
            }

            // read, transform and write data.
            rc = copyData(decrypt, sk, ivdata, file_in_p,
                file_out_p, MD5_BYTE_SIZE, 0);
            if (rc < 0) {
                // delete file since copy failed
                if (was_file_created)
                    vfs_unlink(
                        file_out_p - > f_path.dentry - > d_parent - > d_inode,
                        file_out_p - > f_path.dentry,
                        delegated_inode);
                ret = -ENOMEM;
                goto out;
            }
        } else {
            pr_debug("no access");
            ret = -EACCES;
            goto out;
        }
    } else if (flag_operation_requested == 4) { // Copy operation
        // read, transform and write data.
        copyData(do_nothing, sk, ivdata, file_in_p, file_out_p, 0, 0);
    } else {
        pr_debug("Unknown flag");
        goto out;
    }

    out:
        pr_debug("done\n");
    if (e_struct != NULL && e_struct - > infile)
        kfree(e_struct - > infile);
    if (e_struct != NULL && e_struct - > outfile)
        kfree(e_struct - > outfile);
    if (e_struct != NULL && e_struct - > keybuf)
        kfree(e_struct - > keybuf);
    if (sk != NULL && sk - > tfm)
        crypto_free_skcipher(sk - > tfm);
    if (sk != NULL && sk - > req)
        skcipher_request_free(sk - > req);
    return ret;
}

static int __init init_sys_cpenc(void) {
    pr_info("installed new sys_cpenc module\n");
    if (sysptr == NULL)
        sysptr = cpenc;
    return 0;
}
static void __exit exit_sys_cpenc(void) {
    if (sysptr != NULL)
        sysptr = NULL;
    pr_info("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_AUTHOR("ssheriff");
MODULE_LICENSE("GPL");

/*
*  daifs.c
*  Copyright (C) 2017 daikunhai@hikvision.com
*  2017-11-25
*/
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>
#include <linux/mtd/super.h>
#include "daifs.h"

//#define DEBUG_DAIFS

#ifdef DEBUG_DAIFS
#define DEBUG_PRINT(fmt, args...) printk("daifs:" fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...) 
#endif

//static const struct super_operations daifs_ops;
static const struct inode_operations daifs_dir_inode_operations;
static const struct file_operations daifs_directory_operations;
static const struct address_space_operations daifs_aops;

#define DAIFS_MTD_READ(sb, ...) ((sb)->s_mtd->read((sb)->s_mtd, ##__VA_ARGS__))

struct daifs_inode *daifs_inode_table;

static struct inode *get_daifs_inode(struct super_block *sb,
	const struct daifs_inode *daifs_inode, unsigned int offset)
{
	struct inode *inode;
	
	inode = iget_locked(sb, offset);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	
	if (!(inode->i_state & I_NEW))
		return inode;
	DEBUG_PRINT("daifs_inode->i_mode = %x\n", daifs_inode->i_mode);
	switch (daifs_inode->i_mode) {
		case NORMAL_FILE:
			inode->i_fop = &generic_ro_fops;
			inode->i_data.a_ops = &daifs_aops;
			inode->i_mode = S_IFREG  | 0644;
			break;
		case DIRECTORY_FILE:
			inode->i_op = &daifs_dir_inode_operations;
			inode->i_fop = &daifs_directory_operations;
			inode->i_mode = S_IFDIR  | 0644;
			break;
		default:
			init_special_inode(inode, daifs_inode->i_mode, 0);//FIXME!!
	}
	
	inode->i_private = (void *)daifs_inode;
	if(daifs_inode->i_num == 0) {  // root
		inode->i_mode |= (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}
	inode->i_size = daifs_inode->i_length;
	
	unlock_new_inode(inode);
	
	return inode;
}

int daifs_read_mtd(struct super_block *sb, unsigned long pos,
		   void *buf, size_t buflen)
{
	int ret;
	size_t rlen;

	if (sb->s_mtd) {
		DEBUG_PRINT("mtd name:%s\n", sb->s_mtd->name);
		DEBUG_PRINT("pos = %ld, buflen= %d\n", pos, buflen);

		ret = DAIFS_MTD_READ(sb, pos, buflen, &rlen, buf);
		return (ret < 0 || rlen != buflen) ? -EIO : 0;
	}
	printk("daifs:read mtd failed! No device!\n");
	return -EIO;
}

static void daifs_put_super(struct super_block *sb)
{
	sync_filesystem(sb);

	if(sb->s_fs_info)
		kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

static int daifs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb; 
	u64 id;

	if(!dentry->d_sb)
		return -1;
	sb = dentry->d_sb;

	if(!sb->s_bdev)//use mount_mtd we can't find this! FIXME!!
		return -1;
	if(!sb->s_bdev->bd_dev)
		return -1;

	id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = DAIFS_MAGIC;
	buf->f_namelen = DAIFS_MAX_FILE_NAME;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_bfree = 0;//buf->f_bavail = buf->f_ffree;
	buf->f_blocks = 0;  //FIXME!!!
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static int daifs_remount(struct super_block *sb, int *flags, char *data)
{
	*flags |= MS_RDONLY;
	return 0;
}

/*
* 读指定目录下的目录项
 */
static int daifs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct daifs_inode *daifs_i;
	unsigned int f_inode;
	int i;
	int ret;
	char file_name[DAIFS_MAX_FILE_NAME] = {0};
	int length;
	int count = 0;
	int offset = 0;

	offset = filp->f_pos;

	daifs_i = (struct daifs_inode *)inode->i_private;
	i = daifs_i->i_num + 1; //next inode
	f_inode = daifs_i->i_num;
	DEBUG_PRINT(" daifs_readdir:offset = %d, f_inode=%d\n", offset, f_inode);
	if(offset != 0 && daifs_inode_table[offset].i_father_num ==  f_inode) {
		filp->f_pos = 0;
		return 0;
	}

	for(; i < MAX_INODE_NUMBER; i++) {
		if(daifs_inode_table[i].i_father_num == f_inode) {
			offset = i;
			length = strlen(daifs_inode_table[i].i_name);
			strncpy(file_name, daifs_inode_table[i].i_name, length);

			ret = filldir(dirent, file_name, length, offset,  \
				                 daifs_inode_table[i].i_num,   \
				                 daifs_inode_table[i].i_mode);
			if (ret)
				break;
			
			filp->f_pos = offset;
			count++;
		} else if(daifs_inode_table[i].i_father_num < f_inode)
			break;
	}

	return 0;
}

/*
* 从指定目录找到指定文件的inode
 */
static struct dentry * daifs_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct daifs_inode *dir_inode;
	struct inode *inode = NULL;
	unsigned long i_offset = 0;
	unsigned int f_inode;
	int i;

	dir_inode = (struct daifs_inode *)dir->i_private;
	DEBUG_PRINT(" daifs_lookup:dir-name:%s\n", dir_inode->i_name);

	i = dir_inode->i_num + 1;
	f_inode = dir_inode->i_num;
	for(; i < MAX_INODE_NUMBER; i++) {
		if(daifs_inode_table[i].i_father_num == f_inode) {
			DEBUG_PRINT("daifs_lookup: inode %d\n", daifs_inode_table[i].i_num);
			if(!strcmp(daifs_inode_table[i].i_name, dentry->d_name.name)) {
				i_offset = daifs_inode_table[i].i_num;
				goto FOUND;
			}
			else
				continue;
		} else if(daifs_inode_table[i].i_father_num < f_inode)
			break;
	}

	DEBUG_PRINT("Not found!\n");
	inode = NULL;
	goto NOT_FOUND;


FOUND:
	inode = get_daifs_inode(dir->i_sb, &daifs_inode_table[i], i_offset);
	DEBUG_PRINT("Found file:%s\n", daifs_inode_table[i].i_name);

NOT_FOUND:
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	d_add(dentry, inode); //这里dentry目录项是VFS中的概念，daifs中没有，通过获取inode，
                             //使用d_add来初始化dentry，并添加到内核中去
	return NULL;
}

static int daifs_readpage(struct file *file, struct page * page)
{
	struct inode *inode = page->mapping->host;
	struct daifs_inode *d_inode;
	unsigned int offset, size;
	unsigned long fillsize, pos;
	void *buf;
	int ret;

	buf = kmap(page);
	if (!buf)
		return -ENOMEM;

	offset = page_offset(page);
	size = i_size_read(inode);

	fillsize = 0;
	ret = 0;
	if (offset < size) {
		size -= offset;
		fillsize = size > DAIFS_PAGE_SIZE ? DAIFS_PAGE_SIZE : size;

		d_inode = (struct daifs_inode *)(inode->i_private);
		pos = d_inode->i_offset * DAIFS_PAGE_SIZE + offset;

		ret = daifs_read_mtd(inode->i_sb, pos, buf, fillsize);
		if (ret < 0) {
			DEBUG_PRINT("readpage failed!\n");
			SetPageError(page);
			fillsize = 0;
			ret = -EIO;
			goto out;
		}

		if(size - DAIFS_PAGE_SIZE > 0) {
			 if(size - DAIFS_PAGE_SIZE > DAIFS_PAGE_SIZE)
			 	fillsize = DAIFS_PAGE_SIZE;
			 else
			 	fillsize = size - DAIFS_PAGE_SIZE;

			pos = d_inode->i_offset * DAIFS_PAGE_SIZE + offset + DAIFS_PAGE_SIZE;

			ret = daifs_read_mtd(inode->i_sb, pos, buf + DAIFS_PAGE_SIZE, fillsize);
			if (ret < 0) {
				DEBUG_PRINT("readpage failed!\n");
				SetPageError(page);
				fillsize = 0;
				ret = -EIO;
			}
			fillsize += DAIFS_PAGE_SIZE;
		}
	}

out:
	if (fillsize < PAGE_SIZE)
		memset(buf + fillsize, 0, PAGE_SIZE - fillsize);
	if (ret == 0)
		SetPageUptodate(page);

	flush_dcache_page(page);
	kunmap(page);
	unlock_page(page);
	return ret;


}

static const struct address_space_operations daifs_aops = {
	.readpage = daifs_readpage
};

static const struct file_operations daifs_directory_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= daifs_readdir,
};

static const struct inode_operations daifs_dir_inode_operations = {
	.lookup		= daifs_lookup,
};

static const struct super_operations daifs_super_ops = {
	.put_super	= daifs_put_super,
	.remount_fs	= daifs_remount,
	.statfs		= daifs_statfs,
};

static int romfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int ret = 0;
	char *header_data;
	struct daifs_super_block *dai_sb;
	struct inode *root;

	header_data = kmalloc(HEADER_DATA_LEN, GFP_KERNEL);
	if(header_data == NULL) {
		printk("kmalloc failed!\n");
		return -1;
	}

	memset(header_data, 0, HEADER_DATA_LEN);

	ret = daifs_read_mtd(sb, 0, header_data, HEADER_DATA_LEN);
	if(ret < 0)
		goto error_rmtd;

	sb->s_maxbytes = 0xFFFFFFFF;
	sb->s_magic = DAIFS_MAGIC;
	sb->s_flags |= MS_RDONLY | MS_NOATIME;
	sb->s_op = &daifs_super_ops;

	daifs_inode_table = (struct daifs_inode*)(header_data + SUPER_BLOCK_SIZE);
	dai_sb = (struct daifs_super_block *)header_data;
	if(dai_sb->s_word0 != DAIFS_MAGIC || dai_sb->s_word1 != DAIFS_MAGIC) {
		printk("%x, %x\n", dai_sb->s_word0, dai_sb->s_word1);
		printk("Worng daifs magic!!!\n");
		ret = -EINVAL;
		goto error_rmtd;
	}
	
	sb->s_fs_info = (void *)header_data;

	printk("Filesystem name : daifs\r\n");
	printk("         Author : %s\r\n", dai_sb->s_name);
	
	root = get_daifs_inode(sb, &daifs_inode_table[0], 0);
	if (!root) {
		printk("daifs:get root inode failed!\n");
		goto error_rmtd;
	}
	sb->s_root = d_alloc_root(root);
	if (!sb->s_root) {
		iput(root);
		printk("daifs:root dir alloc failed!\n");
		goto error_rmtd;
	}
	
	return 0;

error_rmtd:
	kfree(header_data);
	return ret;
}

static void daifs_kill_sb(struct super_block *sb)
{
	if (sb->s_mtd) {
		kill_mtd_super(sb);
		return;
	}
}

static struct dentry *daifs_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name,
			void *data)
{
	struct dentry *ret = ERR_PTR(-EINVAL);

	ret = mount_mtd(fs_type, flags, dev_name, data, romfs_fill_super);
	return ret;
}

static struct file_system_type daifs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "daifs",
	.mount		= daifs_mount,
	.kill_sb	= daifs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_daifs(void)
{
	int ret;

	ret = register_filesystem(&daifs_fs_type);
	if (ret) {
		pr_err("Failed to register filesystem\n");
		goto error_register;
	}

	return 0;

error_register:
	return ret;
}

static void __exit exit_daifs(void)
{
	unregister_filesystem(&daifs_fs_type);
}

module_init(init_daifs);
module_exit(exit_daifs);

MODULE_DESCRIPTION("MTD ReadOnly daifs");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("daikunhai");

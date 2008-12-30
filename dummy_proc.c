/*
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/seq_file.h>

#include <net/netlink.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chou Chifeng <cfchou@gmail.com>");
MODULE_DESCRIPTION("dummy proc/seq");
MODULE_ALIAS("dummy_proc");

#define DEBUGP printk

#define NLK_DBG_ENABLE	"dummy_dbg_enable"
#define NLK_DBG_INFO	"dummy_dbg_info"

struct sni_t
{
#define SNI_LEN	255
	struct list_head list;
	char data[SNI_LEN + 1];
};

static spinlock_t sni_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(sni_list);

static struct proc_dir_entry *sne_entry = NULL;
static struct proc_dir_entry *sni_entry = NULL;
static atomic_t sne_cmd = ATOMIC_INIT(0);

static int gen_test_sni(unsigned int count);

// classic proc_fs
/* bash>echo 1 >/proc/dummy_dbg_enable
 * here it receives len == 2 bytes(extra '\n' pended)
 */
static int sne_write(struct file *flip, char const __user *buff,
	unsigned long len, void *data)
{
	char cmd[4];
	size_t sz = sizeof(cmd) - 1;

	struct sni_t *sni, *tmp = NULL;

	memset(cmd, 0, sizeof(cmd));
	DEBUGP(KERN_ALERT "[INFO] length %ld. only take 1st byte\n",
		len);
	if (len < sizeof(cmd))
		sz = len;

	if (copy_from_user(&cmd, buff, sz)) {
		DEBUGP(KERN_ALERT "[ERR] copy_from_user\n");
		return -EFAULT;
	}

	DEBUGP(KERN_ALERT "[INFO] w(%d:%ld): >>%s<<, %d\n", sz, len, cmd,
		(unsigned char)(cmd[0] - '0'));

	if (9 < (unsigned char)(cmd[0] -= '0')) {
		DEBUGP(KERN_ALERT "[ERR] only accept 0 ~ 9\n");
		return -EFAULT;
	}

	atomic_set(&sne_cmd, cmd[0]);
	if (0 == cmd[0]) {
		spin_lock_bh(sni_list_lock);
		// cleanning
		list_for_each_entry_safe(sni, tmp, &sni_list, list) {
			list_del(&sni->list);
			kfree(sni);
		}
		spin_unlock_bh(sni_list_lock);
	} else {
		// gen 10 more tests
		gen_test_sni(10);
	}

	// although truncate to 1 byte, return total avoiding further callbacks 
	return len;
}

static int sne_read(char *page, char **start, off_t off, int count, int *eof,
	void *data)
{
	int len = 0;
	int cmd = 0;
	*eof = 1;
	if (off > 0) {
		return 0;
	}
	cmd = atomic_read(&sne_cmd);
	len = sprintf(page, "%d\n", cmd);
	return len;
}

// seq interface
static void* sni_seq_start(struct seq_file *sfile, loff_t *pos);
static void* sni_seq_next(struct seq_file *sfile, void *v, loff_t *pos);
static void sni_seq_stop(struct seq_file *sfile, void *v);
static int sni_seq_show(struct seq_file *sfile, void *v);

static struct seq_operations sni_seq_ops = {
	.start	= sni_seq_start,
	.next	= sni_seq_next,
	.stop	= sni_seq_stop,
	.show	= sni_seq_show
};

static int sni_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sni_seq_ops);
}

static struct file_operations sni_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= sni_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};

static int gen_test_sni(unsigned int count)
{
	struct sni_t *sni = NULL;
	int i = 0;
	
	while (i++ < count) {
		if (NULL == (sni = kmalloc(sizeof(struct sni_t), GFP_ATOMIC))) {
			DEBUGP(KERN_ALERT "[ERR] %s(%d)> kmalloc failed!\n",
				__FUNCTION__, __LINE__);
			return i;
		}
		memset(sni, 0, sizeof(struct sni_t));
		strncpy(sni->data, "dummy seq test...", SNI_LEN);
		spin_lock_bh(&sni_list_lock);
		list_add(&sni->list, &sni_list);
		spin_unlock_bh(&sni_list_lock);
	}
	return i;
}

static void* sni_seq_start(struct seq_file *sfile, loff_t *pos)
{
	struct sni_t *sni = NULL;
	int i = 0;
	spin_lock_bh(&sni_list_lock);
	list_for_each_entry(sni, &sni_list, list) {
		if(*pos == i++) {
			return sni;
		}
	}
	return NULL;
}

static void* sni_seq_next(struct seq_file *sfile, void *v, loff_t *pos)
{
	struct sni_t *sni = (struct sni_t *)v;
	// 2.6.14 doesn't have it!
	// if (list_is_last(&sni->list, &sni_list))
	if(sni->list.next == &sni_list)
		return NULL;
	(*pos)++;
	return sni->list.next;
}

static void sni_seq_stop(struct seq_file *sfile, void *v)
{
	spin_unlock_bh(&sni_list_lock);
}

static int sni_seq_show(struct seq_file *sfile, void *v)
{
	struct sni_t *sni = (struct sni_t *)v;
	seq_printf(sfile, "(*) %s\n", sni->data);
	return 0;
}


static void dummy_proc_fini(void);

static int __init dummy_proc_init(void)
{
	if (sne_entry || sni_entry) {
		goto fail_init;
	}

	if (NULL == (sne_entry = create_proc_entry(NLK_DBG_ENABLE, S_IWUSR,
		NULL))) {
		DEBUGP(KERN_ALERT "[ERR] create_proc_entry %s failed!\n",
			NLK_DBG_ENABLE);
		goto fail_init;
	}
	sne_entry->read_proc = sne_read;
	sne_entry->write_proc = sne_write;

	// seq
	if (NULL == (sni_entry = create_proc_entry(NLK_DBG_INFO,
		S_IRUSR | S_IRGRP | S_IROTH, NULL))) {
		DEBUGP(KERN_ALERT "[ERR] create_proc_entry %s failed!\n",
			NLK_DBG_INFO);
		goto fail_init;
	}
	sni_entry->proc_fops = &sni_proc_ops;

	return 0;
fail_init:
	dummy_proc_fini();
	return -ENOMEM;
}

static void dummy_proc_fini(void)
{
	struct sni_t *sni, *tmp = NULL;
	remove_proc_entry(NLK_DBG_ENABLE, NULL);
	atomic_set(&sne_cmd, 0);
	remove_proc_entry(NLK_DBG_INFO, NULL);

	spin_lock_bh(sni_list_lock);
	// cleanning
	list_for_each_entry_safe(sni, tmp, &sni_list, list) {
		list_del(&sni->list);
		kfree(sni);
	}
	spin_unlock_bh(sni_list_lock);

	sne_entry = NULL;
	sni_entry = NULL;
}

module_init(dummy_proc_init);
module_exit(dummy_proc_fini);

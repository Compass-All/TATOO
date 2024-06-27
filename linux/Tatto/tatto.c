#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/varanus.h>
#include <linux/mman.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#define DEVICE_NAME "cmap"
#define CLASS_NAME "cmap"
#define HT_MSZ ((1 << 19)+( 1<<19 )+( 1<<16 ))
void *HT_CMAP;

// Device variables
static dev_t ht_num;
static struct cdev ht_device;
static struct class *ht_class;

// Prototype functions
static int ht_open(struct inode *, struct file *);
static int ht_mmap(struct file *, struct vm_area_struct *);
static int ht_close(struct inode *, struct file *);

// Operations allowed
static struct file_operations ht_fops =
{
	.owner = THIS_MODULE,
	.open = ht_open,
	.mmap = ht_mmap,
	.release = ht_close,
};

static int __init ht_init(void) {
	int ret;
	struct device *dev_ret;

	// Register major & minor number for device
	if ((ret = alloc_chrdev_region(&ht_num, 0, 1, DEVICE_NAME)) < 0) {
		printk(KERN_ALERT "[CMAP_ERR] Failed to register device numbers!\n");
		return ret;
	}

	// Register device class
	if (IS_ERR(ht_class = class_create(THIS_MODULE, CLASS_NAME))) {
		unregister_chrdev_region(ht_num, 1);
		printk(KERN_ALERT "[CMAP_ERR] Failed to register device class!\n");
		return PTR_ERR(ht_class);
	}

	// Register device driver
	if (IS_ERR(dev_ret = device_create(ht_class, NULL, ht_num, NULL, DEVICE_NAME))) {
		class_destroy(ht_class);
		unregister_chrdev_region(ht_num, 1);
		printk(KERN_ALERT "[CMAP_ERR] Failed to create device!\n");
		return PTR_ERR(dev_ret);
	}

	cdev_init(&ht_device, &ht_fops);
	if ((ret = cdev_add(&ht_device, ht_num, 1)) < 0) {
		device_destroy(ht_class, ht_num);
		class_destroy(ht_class);
		unregister_chrdev_region(ht_num, 1);
		printk(KERN_ALERT "[CMAP_ERR] Failed to add device!\n");
		return ret;
	}

	printk(KERN_ALERT "[CMAP] Module inserted (major = %d)\n", MAJOR(ht_num));
	return 0;
}
#define MAP_SIZE (1 << 19) +( 1<<19 )+( 1<<16 )//(1 << 21)
#define DATA_OFFSET_1 (1<<19)+(1<<16)
#define DATA_OFFSET_2 (1<<19)+(1<<19)+(1<<16)
#define MAP_OFFSET (1<<16)
static int ht_open(struct inode *inodep, struct file *filep) {
	printk("[ht_open]\n");
	if ((HT_CMAP = kmalloc(HT_MSZ, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "[CMAP_ERR] No memory!\n");
		return -ENOMEM;
	}
	//hello=kmalloc(MAP_SIZE,GFP_KERNEL);
	int j=0;
	// set reserved bit for not swapping out
	for (j = 0; j < HT_MSZ; j += PAGE_SIZE)
		SetPageReserved(virt_to_page(((unsigned long)HT_CMAP) + j));

	//komodo_reset_all();
		
	printk("[afl_fuzz] %lx\n",HT_CMAP);
	memset((char*)HT_CMAP,0,sizeof(char)*(MAP_SIZE));
	unsigned long int paddr=0;
	paddr= virt_to_phys((char*)HT_CMAP);
	komodo_set_local_reg(0, (paddr));
	printk("[afl_fuzz] paddr %lx\n",paddr);
	//komodo_set_local_reg(5, (HT_CMAP));
	//unsigned long int trace_bits = komodo_info_sp_offset(6);//shmat(shm_id, NULL, 0);//
	//printk("[afl_fuzz] trace_bits %lx\n",trace_bits);
	//unsigned long int trace_bits1 = komodo_info_sp_offset(5);
	//printk("[afl_fuzz] trace_bits %lx\n",trace_bits1);	

	return 0;
}

static int ht_mmap(struct file *filep, struct vm_area_struct *vma) {
	printk("[ht_mmap]\n");
	// PAGE_SIZE as unit
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

        printk("[ht_mmap] size %d  HT_MSZ %d   vm_end  %d  vm_start  %d \n",size,HT_MSZ,(unsigned long)(vma->vm_end),(unsigned long)(vma->vm_start));
	if (size != HT_MSZ) {
		printk(KERN_ALERT "[CMAP_ERR] mmap() size too big!\n");
		return -EINVAL;
	}


	// remap to userspace
	if (remap_pfn_range(vma,
				vma->vm_start,
				virt_to_pfn(HT_CMAP),
				HT_MSZ,
				vma->vm_page_prot) < 0) {
		printk(KERN_ALERT "[CMAP_ERR] Share memory failed!\n");
		return -EIO;
	}

	return 0;
}

static int ht_close(struct inode *inodep, struct file *filep) {
	return 0;
}

static void __exit ht_cleanup(void) {
	cdev_del(&ht_device);
	device_destroy(ht_class, ht_num);
	class_unregister(ht_class);
	class_destroy(ht_class);
	unregister_chrdev_region(ht_num, 1);
	printk(KERN_ALERT "[CMAP] Module removed\n");
}

module_init(ht_init);
module_exit(ht_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Motherfxxk");
MODULE_DESCRIPTION("CMAP module for htrace");

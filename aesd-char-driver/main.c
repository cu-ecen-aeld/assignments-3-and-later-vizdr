/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Vladimir Zdravkov"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = NULL;
    size_t bytes_to_read;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
    /**
     * TODO: handle read
     */
    if (mutex_lock_interruptible(&dev->lock))
    {
        return -ERESTARTSYS;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &entry_offset);
    if (entry == NULL)
    {
        retval = 0;
        goto out;
    }

    bytes_to_read = min(count, entry->size - entry_offset);

    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read))
    {
        retval = -EFAULT;
        goto out;
    }

    *f_pos += bytes_to_read;
    retval = bytes_to_read;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = 0u;

    struct aesd_dev *dev = filp->private_data;
    char *new_buf;
    size_t new_size;
    ssize_t written = 0;
    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    /**
     * TODO: handle write
     */

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    new_buf = kmalloc(count, GFP_KERNEL);
    if (!new_buf) {
        retval = -ENOMEM;
        goto out;
    }

    // Copy data from user space to kernel buffer
    if (copy_from_user(new_buf, buf, count)) {
        retval = -EFAULT;
        kfree(new_buf);
        goto out;
    }
    // Reallocate working_entry buffer to hold new data
    new_size = dev->working_entry.size + count;
    dev->working_entry.buffptr = krealloc(dev->working_entry.buffptr, new_size, GFP_KERNEL);
    if (!dev->working_entry.buffptr) {
        kfree(new_buf);
        retval = -ENOMEM;
        goto out;
    }
    // Append new data to working_entry buffer
    memcpy(dev->working_entry.buffptr + dev->working_entry.size, new_buf, count);
    dev->working_entry.size = new_size;
    kfree(new_buf);
    // Check for newline character to determine if we should add the entry to the circular buffer
    if (memchr(dev->working_entry.buffptr, '\n', dev->working_entry.size)) {
        struct aesd_buffer_entry new_entry;
        new_entry.buffptr = dev->working_entry.buffptr;
        new_entry.size = dev->working_entry.size;
        aesd_circular_buffer_add_entry(&dev->circular_buffer, &new_entry);
        dev->working_entry.buffptr = NULL;
        dev->working_entry.size = 0;
    }

    written = count;
    retval = written;

    out:
    mutex_unlock(&dev->lock);
    
    /**
     * TODO: handle write
     */
    return retval;
}
struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");

    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    // Initialize circular buffer
    aesd_circular_buffer_init(&aesd_device.circular_buffer);

    // Initialize mutex
    mutex_init(&aesd_device.lock);

    // Initialize working entry
    aesd_device.working_entry.buffptr = NULL;
    aesd_device.working_entry.size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry *entry;
    uint8_t index;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    // Free up circular buffer entries

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index)
    {
        if (entry->buffptr)
        {
            kfree(entry->buffptr);
        }
    }

    // Clean up working entry
    if (aesd_device.working_entry.buffptr)
    {
        kfree(aesd_device.working_entry.buffptr);
    }

    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
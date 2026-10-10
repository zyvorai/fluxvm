// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Zyvor AI Labs
// Linux guest driver for FluxVM's macOS 27 custom Virtio device (ID 0x3f).
#include <linux/completion.h>
#include <linux/crc32.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/virtio.h>
#include <linux/version.h>
#include <linux/virtio_config.h>

#define VIRTIO_ID_FLUXVM 0x3f
#define FLUXVM_MAX_FRAME (1U << 20)
#define FLUXVM_BULK_TEST_MAX (1U << 20)
#define FLUXVM_IOC_MAGIC 0xF5

struct fluxvm_bulk_test {
    __u32 length;
    __u8 value;
    __u8 reserved[3];
    __u32 crc32;
};
#define FLUXVM_IOC_BULK_TEST _IOWR(FLUXVM_IOC_MAGIC, 1, struct fluxvm_bulk_test)

struct fluxvm_xact {
    struct completion done;
    unsigned int used;
};

struct fluxvm_dev;
struct fluxvm_channel {
    struct miscdevice misc;
    struct fluxvm_dev *fdev;
    unsigned int qindex;
};

struct fluxvm_dev {
    struct virtio_device *vdev;
    struct virtqueue *vq[2];
    struct mutex qlock[2];
    struct fluxvm_channel ctrl;
    struct fluxvm_channel bulk;
};

struct fluxvm_file {
    struct fluxvm_channel *channel;
    struct mutex lock;
    u8 *response;
    size_t response_len;
    size_t response_off;
};

static void fluxvm_vq_done(struct virtqueue *vq)
{
    struct fluxvm_xact *x;
    unsigned int len;
    while ((x = virtqueue_get_buf(vq, &len)) != NULL) {
        x->used = len;
        complete(&x->done);
    }
}

static int fluxvm_call(struct fluxvm_channel *ch, const void *req, size_t req_len,
                       void *resp, size_t resp_len, size_t *used)
{
    struct scatterlist out, in, *sgs[2];
    struct fluxvm_xact x;
    int ret;

    if (!req_len || req_len > FLUXVM_MAX_FRAME || !resp_len)
        return -EINVAL;
    init_completion(&x.done);
    x.used = 0;
    sg_init_one(&out, req, req_len);
    sg_init_one(&in, resp, resp_len);
    sgs[0] = &out;
    sgs[1] = &in;

    mutex_lock(&ch->fdev->qlock[ch->qindex]);
    ret = virtqueue_add_sgs(ch->fdev->vq[ch->qindex], sgs, 1, 1, &x, GFP_KERNEL);
    if (!ret) {
        virtqueue_kick(ch->fdev->vq[ch->qindex]);
        /* The token lives on this stack frame. Do not time out and leave a
         * dangling token in the virtqueue: a later host completion would
         * otherwise complete freed stack memory. The VZ host backend always
         * returns each consumed chain; VM stop/reset tears down the virtqueue. */
        wait_for_completion(&x.done);
        *used = min_t(size_t, x.used, resp_len);
    }
    mutex_unlock(&ch->fdev->qlock[ch->qindex]);
    return ret;
}

static int fluxvm_open(struct inode *inode, struct file *file)
{
    struct miscdevice *misc = file->private_data;
    struct fluxvm_channel *channel = container_of(misc, struct fluxvm_channel, misc);
    struct fluxvm_file *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;
    ctx->channel = channel;
    mutex_init(&ctx->lock);
    file->private_data = ctx;
    return 0;
}

static int fluxvm_release(struct inode *inode, struct file *file)
{
    struct fluxvm_file *ctx = file->private_data;
    if (ctx) {
        kfree(ctx->response);
        kfree(ctx);
    }
    return 0;
}

static ssize_t fluxvm_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct fluxvm_file *ctx = file->private_data;
    u8 *req, *resp;
    size_t used = 0;
    int ret;

    if (!count || count > FLUXVM_MAX_FRAME)
        return -EMSGSIZE;
    req = memdup_user(buf, count);
    if (IS_ERR(req))
        return PTR_ERR(req);
    resp = kzalloc(FLUXVM_MAX_FRAME, GFP_KERNEL);
    if (!resp) { kfree(req); return -ENOMEM; }

    mutex_lock(&ctx->lock);
    ret = fluxvm_call(ctx->channel, req, count, resp, FLUXVM_MAX_FRAME, &used);
    kfree(req);
    if (!ret) {
        kfree(ctx->response);
        ctx->response = resp;
        ctx->response_len = used;
        ctx->response_off = 0;
    } else {
        kfree(resp);
    }
    mutex_unlock(&ctx->lock);
    return ret ? ret : count;
}

static ssize_t fluxvm_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct fluxvm_file *ctx = file->private_data;
    size_t n;
    mutex_lock(&ctx->lock);
    if (!ctx->response || ctx->response_off >= ctx->response_len) {
        mutex_unlock(&ctx->lock);
        return 0;
    }
    n = min(count, ctx->response_len - ctx->response_off);
    if (copy_to_user(buf, ctx->response + ctx->response_off, n)) {
        mutex_unlock(&ctx->lock);
        return -EFAULT;
    }
    ctx->response_off += n;
    mutex_unlock(&ctx->lock);
    return n;
}

static long fluxvm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct fluxvm_file *ctx = file->private_data;
    struct fluxvm_bulk_test t;
    u8 *area, *reply;
    char request[256];
    size_t used = 0;
    int ret, n;
    u32 crc;

    if (cmd != FLUXVM_IOC_BULK_TEST || ctx->channel->qindex != 1)
        return -ENOTTY;
    if (copy_from_user(&t, (void __user *)arg, sizeof(t)))
        return -EFAULT;
    if (!t.length || t.length > FLUXVM_BULK_TEST_MAX)
        return -EINVAL;

    area = kmalloc(t.length, GFP_KERNEL | __GFP_ZERO);
    reply = kzalloc(4096, GFP_KERNEL);
    if (!area || !reply) { kfree(area); kfree(reply); return -ENOMEM; }
    n = scnprintf(request, sizeof(request),
        "{\"version\":1,\"request_id\":\"bulk-test\",\"operation\":\"bulk-fill\","
        "\"payload\":{\"physical_address\":\"%llu\",\"length\":\"%u\",\"value\":\"%u\"}}",
        (unsigned long long)virt_to_phys(area), t.length, t.value);
    ret = fluxvm_call(ctx->channel, request, n, reply, 4096, &used);
    if (ret)
        goto out;
    if (memchr_inv(area, t.value, t.length)) { ret = -EIO; goto out; }
    crc = crc32_le(~0U, area, t.length) ^ ~0U;
    t.crc32 = crc;
    if (copy_to_user((void __user *)arg, &t, sizeof(t)))
        ret = -EFAULT;
out:
    kfree(area);
    kfree(reply);
    return ret;
}

static const struct file_operations fluxvm_fops = {
    .owner = THIS_MODULE,
    .open = fluxvm_open,
    .release = fluxvm_release,
    .read = fluxvm_read,
    .write = fluxvm_write,
    .unlocked_ioctl = fluxvm_ioctl,
    .llseek = noop_llseek,
};

static int fluxvm_probe(struct virtio_device *vdev)
{
    struct fluxvm_dev *d;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    struct virtqueue_info vqs_info[] = {
        { .name = "control", .callback = fluxvm_vq_done },
        { .name = "bulk", .callback = fluxvm_vq_done },
    };
#else
    vq_callback_t *callbacks[] = { fluxvm_vq_done, fluxvm_vq_done };
    const char *names[] = { "control", "bulk" };
#endif
    int ret;

    d = devm_kzalloc(&vdev->dev, sizeof(*d), GFP_KERNEL);
    if (!d)
        return -ENOMEM;
    d->vdev = vdev;
    mutex_init(&d->qlock[0]);
    mutex_init(&d->qlock[1]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    ret = virtio_find_vqs(vdev, 2, d->vq, vqs_info, NULL);
#else
    ret = virtio_find_vqs(vdev, 2, d->vq, callbacks, names, NULL);
#endif
    if (ret)
        return ret;

    d->ctrl = (struct fluxvm_channel){ .fdev = d, .qindex = 0,
        .misc = { .minor = MISC_DYNAMIC_MINOR, .name = "fluxvm", .fops = &fluxvm_fops, .mode = 0600 } };
    d->bulk = (struct fluxvm_channel){ .fdev = d, .qindex = 1,
        .misc = { .minor = MISC_DYNAMIC_MINOR, .name = "fluxvm-bulk", .fops = &fluxvm_fops, .mode = 0600 } };
    ret = misc_register(&d->ctrl.misc);
    if (ret) goto fail_vqs;
    ret = misc_register(&d->bulk.misc);
    if (ret) goto fail_ctrl;
    virtio_device_ready(vdev);
    vdev->priv = d;
    dev_info(&vdev->dev, "FluxVM custom Virtio device ready\n");
    return 0;
fail_ctrl:
    misc_deregister(&d->ctrl.misc);
fail_vqs:
    vdev->config->del_vqs(vdev);
    return ret;
}

static void fluxvm_remove(struct virtio_device *vdev)
{
    struct fluxvm_dev *d = vdev->priv;
    virtio_reset_device(vdev);
    misc_deregister(&d->bulk.misc);
    misc_deregister(&d->ctrl.misc);
    vdev->config->del_vqs(vdev);
}

static const struct virtio_device_id fluxvm_id_table[] = {
    { VIRTIO_ID_FLUXVM, VIRTIO_DEV_ANY_ID },
    { 0 },
};
MODULE_DEVICE_TABLE(virtio, fluxvm_id_table);

static struct virtio_driver fluxvm_driver = {
    .driver.name = "virtio_fluxvm",
    .driver.owner = THIS_MODULE,
    .id_table = fluxvm_id_table,
    .probe = fluxvm_probe,
    .remove = fluxvm_remove,
};
module_virtio_driver(fluxvm_driver);
MODULE_DESCRIPTION("Zyvor FluxVM custom Virtio guest driver");
MODULE_AUTHOR("Zyvor AI Labs");
MODULE_LICENSE("GPL");

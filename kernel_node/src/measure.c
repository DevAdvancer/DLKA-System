#include "../include/attest_lkm.h"

static struct crypto_shash *sha256_tfm = NULL;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;

static int init_kallsyms_lookup(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        MEASURE_LOG_INFO("Failed to register kprobe for kallsyms_lookup_name: %d\n", ret);
        return ret;
    }

    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!my_kallsyms_lookup_name) {
        MEASURE_LOG_INFO("Failed to get kallsyms_lookup_name address\n");
        return -EFAULT;
    }

    MEASURE_LOG_INFO("kallsyms_lookup_name acquired successfully\n");
    return 0;
}

int get_kernel_text_bounds(unsigned long *start, unsigned long *end)
{
    unsigned long addr = my_kallsyms_lookup_name("_stext");

    if (!addr) {
        MEASURE_LOG_INFO("Failed to locate _stext symbol\n");
        return -ENOENT;
    }

    *start = addr;
    *end = addr + 0x1000;

    MEASURE_LOG_INFO("Kernel text bounds: 0x%lx - 0x%lx\n", *start, *end);
    return 0;
}

int compute_kernel_hash(char *hash_output, size_t out_len)
{
    struct shash_desc *desc;
    unsigned char hash[32];
    unsigned long text_start, text_end;
    void *sample_ptr;
    size_t sample_size;
    int i, ret;

    if (!sha256_tfm || out_len < HASH_OUTPUT_SIZE) {
        return -EINVAL;
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256_tfm),
                   GFP_KERNEL);
    if (!desc) {
        MEASURE_LOG_INFO("Failed to allocate hash descriptor\n");
        return -ENOMEM;
    }

    desc->tfm = sha256_tfm;

    ret = crypto_shash_init(desc);
    if (ret) {
        MEASURE_LOG_INFO("Failed to initialize hash: %d\n", ret);
        goto out;
    }

    ret = get_kernel_text_bounds(&text_start, &text_end);
    if (ret) {
        text_start = my_kallsyms_lookup_name("sys_call_table");
        if (!text_start) {
            text_start = (unsigned long)&init_task;
        }
        sample_ptr = (void *)text_start;
        sample_size = sizeof(unsigned long);
    } else {
        sample_ptr = (void *)text_start;
        sample_size = min((size_t)(text_end - text_start), (size_t)4096);
    }

    MEASURE_LOG_INFO("Hashing %zu bytes from 0x%px\n", sample_size, sample_ptr);

    ret = crypto_shash_update(desc, (u8 *)sample_ptr, sample_size);
    if (ret) {
        MEASURE_LOG_INFO("Hash update failed: %d\n", ret);
        goto out;
    }

    ret = crypto_shash_final(desc, hash);
    if (ret) {
        MEASURE_LOG_INFO("Hash finalization failed: %d\n", ret);
        goto out;
    }

    for (i = 0; i < 32; i++) {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[64] = '\0';

    MEASURE_LOG_INFO("Computed hash: %.16s...%s\n",
                     hash_output, hash_output + 48);

    attest_state_lock();
    if (g_attest_state) {
        g_attest_state->measurement_count++;
        g_attest_state->last_measurement_time = ktime_get();
    }
    attest_state_unlock();

out:
    kfree(desc);
    return ret;
}

int compute_module_hash(const char *module_name, char *hash_output, size_t out_len)
{
    MEASURE_LOG_INFO("Module hash requested for: %s (not yet implemented)\n",
                     module_name);

    snprintf(hash_output, out_len, "MODULE_HASH_PLACEHOLDER_FOR_%s", module_name);
    return 0;
}

int measure_init(void)
{
    int ret;

    ret = init_kallsyms_lookup();
    if (ret) {
        return ret;
    }

    sha256_tfm = crypto_alloc_shash("sha256", 0, 0);

    if (IS_ERR(sha256_tfm)) {
        MEASURE_LOG_INFO("Failed to allocate SHA256 transform: %ld\n",
                        PTR_ERR(sha256_tfm));
        return PTR_ERR(sha256_tfm);
    }

    MEASURE_LOG_INFO("Measurement engine initialized (SHA256)\n");
    return 0;
}

void measure_exit(void)
{
    if (sha256_tfm && !IS_ERR(sha256_tfm)) {
        crypto_free_shash(sha256_tfm);
        MEASURE_LOG_INFO("Measurement engine released\n");
    }
}

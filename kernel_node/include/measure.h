#ifndef MEASURE_H
#define MEASURE_H

#include <linux/kprobes.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/kallsyms.h>

#define HASH_OUTPUT_SIZE 65

int measure_init(void);
void measure_exit(void);
int compute_kernel_hash(char *hash_output, size_t out_len);
int compute_module_hash(const char *module_name, char *hash_output, size_t out_len);
int get_kernel_text_bounds(unsigned long *start, unsigned long *end);

#endif

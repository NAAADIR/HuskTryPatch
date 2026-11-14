/* Experimental, single-threaded ARM64 translation; not a production sandbox. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct oop_ctx oop_ctx;
oop_ctx *oop_create(const void *image, size_t image_size, size_t code_size, uintptr_t tls);
oop_ctx *oop_create_at(const void *image, size_t image_size, size_t code_offset, size_t code_size, uintptr_t tls);
void oop_destroy(oop_ctx *c);
bool oop_translate(oop_ctx *c);
bool oop_run(oop_ctx *c, uint64_t *result);
bool oop_write(oop_ctx *c, size_t offset, const void *bytes, size_t length);
const uint8_t *oop_guest(const oop_ctx *c);
const uint8_t *oop_cache(const oop_ctx *c);
const char *oop_error(const oop_ctx *c);

// SPDX-License-Identifier: (MIT OR Apache-2.0)
#include "util.h"

enum {
    TEST_FILE_SIZE = 2 * 1024 * 1024,
    TEST_FILE_OFFSET = 0x10000,
};

static char filename[] = "read-XXXXXX";

/*
 * Read a well-known pattern from an offset in a file.
 */
int main(int argc, char **argv)
{
    struct test_opts opts;
    struct blkio *b;
    struct blkioq *q;
    struct blkio_mem_region mem_region;
    struct blkio_completion completion;
    void *buf;     /* I/O buffer */
    void *pattern; /* reference data at TEST_FILE_OFFSET */
    size_t buf_size;
    int fd;

    parse_generic_opts(&opts, argc, argv);

    buf_size = sysconf(_SC_PAGESIZE);

    /* Initialize pattern buffer */
    pattern = malloc(buf_size);
    assert(pattern);
    memset(pattern, 'A', buf_size);

    create_and_connect(&b, &opts, filename, TEST_FILE_SIZE);

    ok(blkio_get_int(b, "fd", &fd));
    assert(fd >= 0);

    assert(pwrite_full(fd, pattern, buf_size, TEST_FILE_OFFSET) == buf_size);

    /* Set up I/O buffer */
    ok(blkio_alloc_mem_region(b, &mem_region, buf_size));
    buf = mem_region.addr;

    ok(blkio_set_int(b, "num-queues", 1));
    ok(blkio_start(b));

    ok(blkio_map_mem_region(b, &mem_region));

    q = blkio_get_queue(b, 0);
    assert(q);

    blkioq_read(q, TEST_FILE_OFFSET, buf, buf_size, NULL, 0);
    assert(blkioq_do_io(q, &completion, 1, 1, NULL) == 1);
    assert(completion.ret == 0);
    assert(memcmp(buf, pattern, buf_size) == 0);

    blkio_destroy(&b);
    return 0;
}
/*
 * uvd_selftest_main.c -- host-side harness for the loader's UVD packing.
 *
 * Not part of any firmware build. tools/test_uvd_fw.py compiles this together
 * with firmware.c (-DUVD_SELFTEST), feeds it a raw image and compares the file
 * it produces with the one tools/uvd_fw.py builds from the same bytes. The two
 * are independent implementations of the same layout, so a disagreement means
 * one of them is wrong -- which is the only check available without a boot, and
 * the layout is exactly where a mistake would be silent.
 *
 *   cc -o uvd_selftest uvd_selftest_main.c firmware_selftest.o
 *   ./uvd_selftest in.img out.bin <ucode_version>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned char u8;

size_t uvd_pack_selftest(u8 *out, const u8 *img, size_t size, uint32_t version);
int uvd_image_ok_selftest(const u8 *img, size_t size, uint32_t *version);

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s IN.img OUT.bin UCODE_VERSION\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *img = malloc(n);
    if (fread(img, 1, n, f) != (size_t)n) {
        fprintf(stderr, "short read of %s\n", argv[1]);
        return 2;
    }
    fclose(f);

    uint32_t version = (uint32_t)strtoul(argv[3], NULL, 0);
    uint32_t seen = 0;
    if (!uvd_image_ok_selftest(img, n, &seen)) {
        fprintf(stderr, "uvd_image_ok rejected %s (%ld bytes)\n", argv[1], n);
        return 1;
    }
    if (seen != version) {
        fprintf(stderr, "version mismatch: image says %#x, expected %#x\n", seen, version);
        return 1;
    }

    u8 *out = malloc(n + 0x1000);
    size_t len = uvd_pack_selftest(out, img, n, version);

    f = fopen(argv[2], "wb");
    if (!f) {
        perror(argv[2]);
        return 2;
    }
    fwrite(out, 1, len, f);
    fclose(f);
    printf("%zu\n", len);
    return 0;
}

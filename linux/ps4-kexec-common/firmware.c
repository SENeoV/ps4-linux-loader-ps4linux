/*
 * ps4-kexec - a kexec() implementation for Orbis OS / FreeBSD
 *
 * Copyright (C) 2015-2016 shuffle2 <godisgovernment@gmail.com>
 * Copyright (C) 2015-2016 Hector Martin "marcan" <marcan@marcan.st>
 *
 * This code is licensed to you under the 2-clause BSD license. See the LICENSE
 * file for more information.
 */

#include "firmware.h"
#include "types.h"
#include "kernel.h"
#include "string.h"
#include "types.h"
#include "crc32.h"
#include "../magic.h"

#define DIR  0040755
#define FILE 0100644

struct firmware_header {
    u32 size_bytes;
    u32 header_size_bytes;
    u16 header_version_major;
    u16 header_version_minor;
    u16 ip_version_major;
    u16 ip_version_minor;
    u32 ucode_version;
    u32 ucode_size_bytes;
    u32 ucode_array_offset_bytes;
    u32 crc32;
    union {
        struct {
            u32 ucode_feature_version;
            u32 jt_offset;
            u32 jt_size;
            u8 end[];
        } gfx1;
        struct {
            u32 ucode_feature_version;
            u32 save_and_restore_offset;
            u32 clear_state_descriptor_offset;
            u32 avail_scratch_ram_locations;
            u32 master_pkt_description_offset;
            u8 end[];
        } rlc1;
        struct {
            u32 ucode_feature_version;
            u32 ucode_change_version;
            u32 jt_offset;
            u32 jt_size;
            u8 end[];
        } sdma1;
        u8 raw[0xe0];
    };
};

static inline char hex(u8 c)
{
    if (c <= 9)
        return '0' + c;
    return 'a' + c - 10;
}

static void hex8(u8 **p, u32 val)
{
    *(*p)++ = hex(val >> 28);
    *(*p)++ = hex((val >> 24) & 0xf);
    *(*p)++ = hex((val >> 20) & 0xf);
    *(*p)++ = hex((val >> 16) & 0xf);
    *(*p)++ = hex((val >> 12) & 0xf);
    *(*p)++ = hex((val >> 8) & 0xf);
    *(*p)++ = hex((val >> 4) & 0xf);
    *(*p)++ = hex(val & 0xf);
}

void cpio_hdr(u8 **p, const char *name, u32 mode, size_t size)
{
    size_t name_len = strlen(name);

    // Pad to 4 byte multiple
    while (((uintptr_t)*p) & 0x3)
        *(*p)++ = 0;

    memcpy(*p, "070701", 6);
    *p += 6;
    hex8(p, 0); // c_ino
    hex8(p, mode); // c_mode
    hex8(p, 0); // c_uid
    hex8(p, 0); // c_gid
    hex8(p, 1); // c_nlink
    hex8(p, 0); // c_mtime
    hex8(p, size); // c_filesize
    hex8(p, 0); // c_maj
    hex8(p, 0); // c_min
    hex8(p, 0); // c_rmaj
    hex8(p, 0); // c_rmin
    hex8(p, name_len + 1); // c_namesize
    hex8(p, 0); // c_chksum
    memcpy(*p, name, name_len);
    *p += name_len;
    *(*p)++ = 0;

    while (((uintptr_t)*p) & 0x3)
        *(*p)++ = 0;
}

struct fw_header_t {
    u64 size_words;
    char *unk_ident;
    u64 unk;
    void *blob;
    u64 unk2;
};

struct fw_info_t {
    struct fw_header_t *rlc;
    struct fw_header_t *sdma0;
    struct fw_header_t *sdma1;
    struct fw_header_t *ce;
    struct fw_header_t *pfp;
    struct fw_header_t *me;
    struct fw_header_t *mec1;
    struct fw_header_t *mec2;
};

struct fw_expected_sizes_t {
    u64 rlc;
    u64 sdma0;
    u64 sdma1;
    u64 ce;
    u64 pfp;
    u64 me;
    u64 mec1;
    u64 mec2;
};
static const struct fw_expected_sizes_t liverpool_fw_sizes = {
    LVP_FW_RLC_SIZE,
    LVP_FW_SDMA_SIZE,
    LVP_FW_SDMA1_SIZE,
    LVP_FW_CE_SIZE,
    LVP_FW_PFP_SIZE,
    LVP_FW_ME_SIZE,
    LVP_FW_MEC_SIZE,
    LVP_FW_MEC2_SIZE
};
static const struct fw_expected_sizes_t gladius_fw_sizes = {
    GL_FW_RLC_SIZE,
    GL_FW_SDMA_SIZE,
    GL_FW_SDMA1_SIZE,
    GL_FW_CE_SIZE,
    GL_FW_PFP_SIZE,
    GL_FW_ME_SIZE,
    GL_FW_MEC_SIZE,
    GL_FW_MEC2_SIZE
};

void copy_edid(u8 **p, int sz)
{
	int i;
	u8 *edid = *p;
	u8 *off_edid = kern.edid;
	
	memset(edid, 0, sz);
    *p += sz;
	
	for(i = 0; i < sz; i++)
		*(edid + i) = *(off_edid + i);
}

void copy_eap_hdd_key(u8 **p)
{
	int i;
	u8 *eap_key = *p;
	u8 *off_eap_key = kern.eap_hdd_key;
	
	memset(eap_key, 0, 0x20);
    *p += 0x20;
	
	for(i = 0; i < 0x20; i++)
	{
		if(i < 0x10)
			*(eap_key + i) = *(off_eap_key + 0xF - i);
		else
			*(eap_key + i) = *(off_eap_key + 0x2F - i);
	}
}

int copy_firmware(u8 **p, const char *name, struct fw_header_t *hdr, size_t expected_size)
{
    kern.printf("Copying %s firmware\n", name);
    if (expected_size != (hdr->size_words * 4)) {
        kern.printf("copy_firmware: %s: expected size %d, got %d\n",
                    name, expected_size, hdr->size_words * 4);
        return 0;
    }

    struct firmware_header *fhdr = (struct firmware_header*)*p;
    memset(fhdr, 0, sizeof(*fhdr));
    *p += sizeof(*fhdr);

    memcpy(*p, hdr->blob, expected_size);

    fhdr->size_bytes = expected_size + sizeof(*fhdr);
    fhdr->header_size_bytes = offsetof(struct firmware_header, raw);
    fhdr->header_version_major = 1;
    fhdr->header_version_minor = 0;
    fhdr->ucode_version = 0x10;
    fhdr->ucode_size_bytes = expected_size;
    fhdr->ucode_array_offset_bytes = sizeof(*fhdr);

    *p += expected_size;

    return 1;
}

int copy_gfx_firmware(u8 **p, const char *name, struct fw_header_t *hdr, size_t expected_size)
{
    struct firmware_header *fhdr = (struct firmware_header*)*p;
    if (!copy_firmware(p, name, hdr, expected_size))
        return 0;

    fhdr->ip_version_major = 7;
    fhdr->ip_version_minor = 2;
    fhdr->header_size_bytes = offsetof(struct firmware_header, gfx1.end);
    fhdr->gfx1.ucode_feature_version = 21;
    fhdr->gfx1.jt_offset = (expected_size & ~0xfff) >> 2;
    fhdr->gfx1.jt_size = (expected_size & 0xfff) >> 2;

    fhdr->crc32 = crc32(0, fhdr->raw, sizeof(fhdr->raw) + expected_size);
    return 1;
}

int copy_rlc_firmware(u8 **p, const char *name, struct fw_header_t *hdr, size_t expected_size)
{
    struct firmware_header *fhdr = (struct firmware_header*)*p;
    if (!copy_firmware(p, name, hdr, expected_size))
        return 0;

    fhdr->ip_version_major = 7;
    fhdr->ip_version_minor = 2;
    fhdr->header_size_bytes = offsetof(struct firmware_header, rlc1.end);
    fhdr->rlc1.ucode_feature_version = 1;
    fhdr->rlc1.save_and_restore_offset = 0x90;
    fhdr->rlc1.clear_state_descriptor_offset = 0x3d;
    fhdr->rlc1.avail_scratch_ram_locations = 0x270; // 0x170 for bonaire, 0x270 for kabini??
    fhdr->rlc1.master_pkt_description_offset = 0;

    fhdr->crc32 = crc32(0, fhdr->raw, sizeof(fhdr->raw) + expected_size);
    return 1;
}

int copy_sdma_firmware(u8 **p, const char *name, struct fw_header_t *hdr, size_t expected_size, int idx)
{
    struct firmware_header *fhdr = (struct firmware_header*)*p;
    if (!copy_firmware(p, name, hdr, expected_size))
        return 0;

    fhdr->ip_version_major = 2;
    fhdr->ip_version_minor = 1;
    fhdr->header_size_bytes = offsetof(struct firmware_header, sdma1.end);
    fhdr->sdma1.ucode_feature_version = idx == 0 ? 9 : 0;
    fhdr->sdma1.ucode_change_version = 0;
    fhdr->sdma1.jt_offset = (expected_size & ~0xfff) >> 2;
    fhdr->sdma1.jt_size = (expected_size & 0xfff) >> 2;

    fhdr->crc32 = crc32(0, fhdr->raw, sizeof(fhdr->raw) + expected_size);
    return 1;
}

static const u32 pfp_nop_handler[] = {
    0xdc120000, //     mov r4, ctr
    0x31144000, //     seteq r5, r4, #0x4000
    0x95400009, //     cbz r5, l0
    0xc4200016, //     ldw r8, [r0, #0x16]
    0xdc030000, //     mov ctr, r0
    0xcc000049, //     stw r0, [r0, #0x49]
    0xcc200013, //     stw r0, [r8, #0x13]
    0xc424007e, //     ldw r9, [r0, #0x7e]
    0x96400000, // l1: cbz r9, l1
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
    0xd440007f, // l0: stm r1, [r0, #0x7f]
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
};

static const u32 ce_nop_handler[] = {
    0xdc120000, //     mov r4, ctr
    0x31144000, //     seteq r5, r4, #0x4000
    0x95400009, //     cbz r5, l0
    0xc420000c, //     ldw r8, [r0, #0xc]
    0xdc030000, //     mov ctr, r0
    0xcc00002f, //     stw r0, [r0, #0x2f]
    0xcc200012, //     stw r0, [r8, #0x12]
    0xc424007e, //     ldw r9, [r0, #0x7e]
    0x96400000, // l1: cbz r9, l1
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
    0xd440007f, // l0: stm r1, [r0, #0x7f]
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
};

static const u32 mec_nop_handler[] = {
    0xdc120000, //     mov r4, ctr
    0x31144000, //     seteq r5, r4, #0x4000
    0x95400009, //     cbz r5, l0
    0xc43c000c, //     ldw r15, [r0, #0x9]
    0xdc030000, //     mov ctr, r0
    0xcc00002b, //     stw r0, [r0, #0x2b]
    0xcc3c000d, //     stw r0, [r15, #0xd]
    0xc424007e, //     ldw r9, [r0, #0x7e]
    0x96400000, // l1: cbz r9, l1
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
    0xd440007f, // l0: stm r1, [r0, #0x7f]
    0x7c408001, //     mov r2, r1
    0x88000000, //     btab
};

#define PACKET_TYPE_NOP 0x10

static void patch_fw(void *p, const u32 *handler, int handler_size) {
    int size = ((struct firmware_header*)p)->ucode_size_bytes;
    int code_size = (size & ~0xfff) / 4;
    int nop_start = code_size - 0x10;

    u32 *fw = p + sizeof(struct firmware_header);
    kern.printf("NOP handler at 0x%x\n", nop_start);
    memcpy(&fw[nop_start], handler, handler_size);

    // patch the branch table entry
    for (int off = code_size; off < size/4; off++) {
        if ((fw[off] >> 16) == PACKET_TYPE_NOP) {
            fw[off] = (PACKET_TYPE_NOP << 16) | nop_start;
        }
    }
}

/* ---------------------------------------------------------------------------
 * UVD microcode
 *
 * gc_get_fw_info()'s table has eight members, all graphics and DMA, so the
 * video engines are not in it. Orbis' UVD images are plain data in kernel
 * rodata instead, and its KMD memcpy()s one of three by GPU id:
 * 0x710f00-0x710f2f -> 1.101.42, above that -> 1.92.43, 0x740fxx (Gladius)
 * -> 1.152.50. Only the Gladius case is unambiguous from here, because
 * gpu_devid_is_9924() answers it and nothing the loader has distinguishes the
 * two Liverpool revisions, so only Gladius gets a file.
 *
 * An image begins with the VCPU reset-vector table in uvd_image_sig and
 * carries "[ATI LIB=UVDFW,x.y.z]" near its end, with the packed version word
 * 0x0c bytes before the tag. Both are checked before anything is copied: a
 * wrong or stale offset is caught and the file is simply left out, which
 * leaves the boot exactly as it was.
 *
 * linux-firmware layout is the firmware_header above, then a 256-byte block
 * ending in the ASCII magic "FWVH", then the image. amdgpu copies the whole
 * array into the VCPU BO and starts the VCPU at BO + 256
 * (AMDGPU_UVD_FIRMWARE_OFFSET), so the FWVH block is carried but never run.
 *
 * Derivation and addresses: docs/uvd-microcode-2026-10-23.md in the ps4 repo.
 * ------------------------------------------------------------------------- */

#define UVD_IP_MAJOR 4
#define UVD_IP_MINOR 2
#define UVD_FWVH_SIZE 256
#define UVD_SCAN_START 0x400000
#define UVD_SCAN_END  0x1000000

static const u8 uvd_image_sig[16] = {
    0x00, 0xc5, 0x49, 0x10, 0xd5, 0x49, 0x20, 0xe5,
    0x49, 0x30, 0xf5, 0x49, 0x00, 0x34, 0x00, 0x00
};
static const char uvd_banner[] = "[ATI LIB=UVDFW,";

static const u8 *find_bytes(const u8 *hay, size_t n, const void *needle, size_t m)
{
    if (m > n)
        return NULL;
    for (size_t i = 0; i + m <= n; i++)
        if (!memcmp(hay + i, needle, m))
            return hay + i;
    return NULL;
}

/* 1 when img[0, size) really is a UVD image; *version gets its version word. */
static int uvd_image_ok(const u8 *img, size_t size, u32 *version)
{
    if (!img || size < 0x10000 || size > UVD_FW_MAX_SIZE)
        return 0;
    if (memcmp(img, uvd_image_sig, sizeof(uvd_image_sig)))
        return 0;
    const u8 *tag = find_bytes(img, size, uvd_banner, sizeof(uvd_banner) - 1);
    if (!tag || (size_t)(tag - img) < 0x10)
        return 0;
    *version = *(const u32 *)(tag - 0x0c);
    return 1;
}

/* Report every UVD image in the kernel image. Runs only when the offset above
 * did not verify, so a new firmware can be read off a boot log. */
static const u8 *uvd_scan(size_t *size_out, u32 *version_out)
{
    const u8 *found = NULL;
    int n = 0;

    for (uintptr_t a = kern.kern_base + UVD_SCAN_START;
         a < kern.kern_base + UVD_SCAN_END; a += 16) {
        const u8 *p = (const u8 *)a;
        if (memcmp(p, uvd_image_sig, sizeof(uvd_image_sig)))
            continue;
        /* bound the candidate by the next signature or the window end */
        size_t span = (kern.kern_base + UVD_SCAN_END) - a;
        if (span > UVD_FW_MAX_SIZE)
            span = UVD_FW_MAX_SIZE;
        u32 ver = 0;
        const u8 *tag = find_bytes(p, span, uvd_banner, sizeof(uvd_banner) - 1);
        if (!tag || (size_t)(tag - p) < 0x10)
            continue;
        ver = *(const u32 *)(tag - 0x0c);
        kern.printf("firmware_extract: UVD image at kern_base+0x%x, version %d.%d.%d\n",
                    (u32)(a - kern.kern_base), (ver >> 24) & 0xff,
                    (ver >> 8) & 0xff, ver & 0xff);
        n++;
        found = p;
        *size_out = (tag - p) + 0x18;   /* through the banner; a floor, not the size */
        *version_out = ver;
    }

    if (n == 1)
        return found;
    if (n > 1)
        kern.printf("firmware_extract: %d UVD images and no offset to choose by, "
                    "skipping\n", n);
    return NULL;
}

static const u8 *locate_uvd_firmware(size_t *size_out, u32 *version_out)
{
    if (!kern.gpu_devid_is_9924 || !kern.gpu_devid_is_9924())
        return NULL;                      /* Liverpool: cannot tell its two apart */

    if (kern.uvd_fw_gladius && kern_sz_uvd_fw_gladius) {
        const u8 *img = (const u8 *)kern.uvd_fw_gladius;
        if (uvd_image_ok(img, kern_sz_uvd_fw_gladius, version_out)) {
            *size_out = kern_sz_uvd_fw_gladius;
            return img;
        }
        kern.printf("firmware_extract: UVD offset did not verify, scanning\n");
    }
    return uvd_scan(size_out, version_out);
}

static void copy_uvd_firmware(u8 **p, const u8 *img, size_t size, u32 version)
{
    struct firmware_header *fhdr = (struct firmware_header *)*p;
    memset(fhdr, 0, sizeof(*fhdr));
    *p += sizeof(*fhdr);

    u8 *array = *p;
    memset(array, 0, UVD_FWVH_SIZE);
    *(u32 *)(array + 0x00) = UVD_FWVH_SIZE + size;
    *(u32 *)(array + 0x08) = 0x00010000;
    *(u32 *)(array + 0x0c) = 0x00010000;
    /* observed on both stock files: the image length less 0xe20 */
    *(u32 *)(array + 0x18) = size > 0xe20 ? (u32)(size - 0xe20) : 0;
    memcpy(array + 0x1c, "FWVH", 4);
    *p += UVD_FWVH_SIZE;

    memcpy(*p, img, size);
    *p += size;

    fhdr->size_bytes = sizeof(*fhdr) + UVD_FWVH_SIZE + size;
    fhdr->header_size_bytes = offsetof(struct firmware_header, raw);
    fhdr->header_version_major = 1;
    fhdr->header_version_minor = 0;
    fhdr->ip_version_major = UVD_IP_MAJOR;
    fhdr->ip_version_minor = UVD_IP_MINOR;
    fhdr->ucode_version = version;
    fhdr->ucode_size_bytes = UVD_FWVH_SIZE + size;
    fhdr->ucode_array_offset_bytes = sizeof(*fhdr);
    fhdr->crc32 = crc32(0, array, UVD_FWVH_SIZE + size);
}

#ifdef UVD_SELFTEST
/* Built only by tools/test_uvd_fw.py, which packs the same image with
 * tools/uvd_fw.py and compares the two files byte for byte. It is the only way
 * to check this layout without a boot, and the layout is where a mistake would
 * be silent: 256 bytes out and the VCPU executes the wrong words. */
size_t uvd_pack_selftest(u8 *out, const u8 *img, size_t size, u32 version)
{
    u8 *p = out;
    copy_uvd_firmware(&p, img, size, version);
    return (size_t)(p - out);
}

int uvd_image_ok_selftest(const u8 *img, size_t size, u32 *version)
{
    return uvd_image_ok(img, size, version);
}
#endif
struct fw_info_t *get_fw_info() {
    if (kern.gc_get_fw_info) {
        return kern.gc_get_fw_info();
    } else if (kern.Starsha_UcodeInfo) {
        return kern.Starsha_UcodeInfo;
    } else {
        return NULL;
    }
}

const struct fw_expected_sizes_t *get_fw_expected_sizes() {
    if (kern.gpu_devid_is_9924 && kern.gpu_devid_is_9924()) {
        return &gladius_fw_sizes;
    } else {
        return &liverpool_fw_sizes;
    }
}

const char * get_gpu_name() {
  if (kern.gpu_devid_is_9924 && kern.gpu_devid_is_9924()) {
      return "gladius";
  } else {
      return "liverpool";
  }
}

ssize_t firmware_extract(void *dest)
{
    u8 *p = dest;

    // Yeah, this calls it Starsha... Liverpool, Starsha, ThebeJ, whatever.
    struct fw_info_t *info = get_fw_info();
    if (!info) {
        kern.printf("firmware_extract: Could not locate firmware table");
        return -1;
    }
    const struct fw_expected_sizes_t *fw_sizes = get_fw_expected_sizes();
	
	//Eap hdd key
	cpio_hdr(&p, "key", DIR, 0);
	cpio_hdr(&p, "key/eap_hdd_key.bin", FILE, 0x20);
	copy_eap_hdd_key(&p);
	
    cpio_hdr(&p, "lib", DIR, 0);
    cpio_hdr(&p, "lib/firmware", DIR, 0);
    
    int ext_blocks = ((unsigned char*)kern.edid)[126];
    int edid_sz = 128 * (1 + ext_blocks);
    cpio_hdr(&p, "lib/firmware/edid", DIR, 0);
    cpio_hdr(&p, "lib/firmware/edid/my_edid.bin", FILE, edid_sz);
	copy_edid(&p, edid_sz);
    
    char dir[7];
    if (kern.gpu_devid_is_9924 && kern.gpu_devid_is_9924())
      kern.snprintf(dir, sizeof(dir), "amdgpu");
    else
      kern.snprintf(dir, sizeof(dir), "amdgpu");

    char dir_path[64];
    kern.snprintf(dir_path, sizeof(dir_path), "lib/firmware/%s/", dir);
    cpio_hdr(&p, dir_path, DIR, 0);

    char pfp_path[64];
    kern.snprintf(pfp_path, sizeof(pfp_path), "%s%s_pfp.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", pfp_path);
    cpio_hdr(&p, pfp_path, FILE, FW_HEADER_SIZE + fw_sizes->pfp);
    u8 *pfp = p;
    if (!copy_gfx_firmware(&p, "PFP", info->pfp, fw_sizes->pfp))
        return -1;
    patch_fw(pfp, pfp_nop_handler, sizeof(pfp_nop_handler));

    char me_path[64];
    kern.snprintf(me_path, sizeof(me_path), "%s%s_me.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", me_path);
    cpio_hdr(&p, me_path, FILE, FW_HEADER_SIZE + fw_sizes->me);
    if (!copy_gfx_firmware(&p, "ME", info->me, fw_sizes->me))
        return -1;

    char ce_path[64];
    kern.snprintf(ce_path, sizeof(ce_path), "%s%s_ce.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", ce_path);
    cpio_hdr(&p, ce_path, FILE, FW_HEADER_SIZE + fw_sizes->ce);
    u8 *ce = p;
    if (!copy_gfx_firmware(&p, "CE", info->ce, fw_sizes->ce))
        return -1;
    patch_fw(ce, ce_nop_handler, sizeof(ce_nop_handler));

    char mec_path[64];
    kern.snprintf(mec_path, sizeof(mec_path), "%s%s_mec.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", mec_path);
    cpio_hdr(&p, mec_path, FILE, FW_HEADER_SIZE + fw_sizes->mec1);
    u8 *mec1 = p;
    if (!copy_gfx_firmware(&p, "MEC", info->mec1, fw_sizes->mec1))
        return -1;
    patch_fw(mec1, mec_nop_handler, sizeof(mec_nop_handler));

    char mec2_path[64];
    kern.snprintf(mec2_path, sizeof(mec2_path), "%s%s_mec2.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", mec2_path);
    cpio_hdr(&p, mec2_path, FILE, FW_HEADER_SIZE + fw_sizes->mec2);
    u8 *mec2 = p;
    if (!copy_gfx_firmware(&p, "MEC2", info->mec2, fw_sizes->mec2))
        return -1;
    patch_fw(mec2, mec_nop_handler, sizeof(mec_nop_handler));

    char rlc_path[64];
    kern.snprintf(rlc_path, sizeof(rlc_path), "%s%s_rlc.bin", dir_path, get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", rlc_path);
    cpio_hdr(&p, rlc_path, FILE, FW_HEADER_SIZE + fw_sizes->rlc);
    if (!copy_rlc_firmware(&p, "RLC", info->rlc, fw_sizes->rlc))
        return -1;

    char sdma_path[64];
    kern.snprintf(sdma_path, sizeof(sdma_path), "%s%s_sdma.bin", dir_path,  get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", sdma_path);
    cpio_hdr(&p, sdma_path, FILE, FW_HEADER_SIZE + fw_sizes->sdma0);
    if (!copy_sdma_firmware(&p, "SDMA", info->sdma0, fw_sizes->sdma0, 0))
        return -1;

    char sdma1_path[64];
    kern.snprintf(sdma1_path, sizeof(sdma1_path), "%s%s_sdma1.bin", dir_path,  get_gpu_name());
    kern.printf("firmware_extract: Extract %s \n", sdma1_path);
    cpio_hdr(&p, sdma1_path, FILE, FW_HEADER_SIZE + fw_sizes->sdma1);
    if (!copy_sdma_firmware(&p, "SDMA1", info->sdma1, fw_sizes->sdma1, 1))
        return -1;
    size_t uvd_size = 0;
    u32 uvd_version = 0;
    const u8 *uvd = locate_uvd_firmware(&uvd_size, &uvd_version);
    if (uvd) {
        char uvd_path[64];
        kern.snprintf(uvd_path, sizeof(uvd_path), "%s%s_uvd.bin", dir_path, get_gpu_name());
        kern.printf("firmware_extract: Extract %s (UVD %d.%d.%d, %d bytes)\n",
                    uvd_path, (uvd_version >> 24) & 0xff, (uvd_version >> 8) & 0xff,
                    uvd_version & 0xff, (int)uvd_size);
        cpio_hdr(&p, uvd_path, FILE, FW_HEADER_SIZE + UVD_FWVH_SIZE + uvd_size);
        copy_uvd_firmware(&p, uvd, uvd_size, uvd_version);
    }

    cpio_hdr(&p, "TRAILER!!!", FILE, 0);

    size_t size = p - (u8*)dest;
    if (size > FW_CPIO_SIZE) {
        kern.printf("firmware_extract: overflow! %d > %d\n", size, FW_CPIO_SIZE);
        return -1;
    }

    return size;
}

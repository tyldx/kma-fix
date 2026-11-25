#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <kallsyms.h>
#include <hook.h>

KPM_NAME("kma-fix");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("tyldx");
KPM_DESCRIPTION("give KMA PTE scratch pages vmalloc backing");

typedef unsigned long u64;
typedef unsigned int u32;

#define SCRATCH_SIZE 0x1000UL
#define SCRATCH_GFP 0xcc0UL
#define MAX_TRACK 64
#define SCAN_BYTES 2048UL

static long (*nofault)(void *dst, const void *src, unsigned long size);
static void *(*vmalloc_fn)(unsigned long size);
static void (*vfree_fn)(const void *p);
static u64 memstart, page_offset, linear_size, init_mm_addr;
static void *glp_addr, *alloc_addr, *free_addr;
static u64 tracked[MAX_TRACK];
static int lock;
static u64 n_scratch, n_other, n_nomem, n_freed, n_guard;
static u64 last_dist;

static int rd(u64 va, u64 *out)
{
    return nofault(out, (const void *)va, 8);
}

static int in_linear(u64 va)
{
    return va >= page_offset && va < page_offset + linear_size;
}

static int linear_block(u64 va)
{
    u64 ttbr1, pa, d, tva;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    pa = ttbr1 & 0x0000fffffffff000UL;
    tva = page_offset + (pa - memstart) + ((va >> 30) & 0x1ffUL) * 8;
    if (rd(tva, &d))
        return 0;
    if ((d & 3) == 1)
        return 1;
    if ((d & 3) != 3)
        return 0;
    pa = d & 0x0000fffffffff000UL;
    tva = page_offset + (pa - memstart) + ((va >> 21) & 0x1ffUL) * 8;
    if (rd(tva, &d))
        return 0;
    return (d & 3) == 1;
}

static void lock_take(void)
{
    while (__atomic_exchange_n(&lock, 1, __ATOMIC_ACQUIRE))
        ;
}

static void lock_drop(void)
{
    __atomic_store_n(&lock, 0, __ATOMIC_RELEASE);
}

static int track_add(u64 p)
{
    int i, ok = 0;
    lock_take();
    for (i = 0; i < MAX_TRACK; i++) {
        if (!tracked[i]) {
            tracked[i] = p;
            ok = 1;
            break;
        }
    }
    lock_drop();
    return ok;
}

static int track_take(u64 p)
{
    int i, ok = 0;
    lock_take();
    for (i = 0; i < MAX_TRACK; i++) {
        if (tracked[i] == p) {
            tracked[i] = 0;
            ok = 1;
            break;
        }
    }
    lock_drop();
    return ok;
}

static int track_count(void)
{
    int i, n = 0;
    lock_take();
    for (i = 0; i < MAX_TRACK; i++)
        if (tracked[i])
            n++;
    lock_drop();
    return n;
}

static int site_match(u64 w)
{
    u64 lb = w & 0xfffUL;
    u32 f0, f1, f2, f3, f4;
    u64 t0, t1, t2;
    if (w < 0xffffffc000000000UL)
        return 0;
    if (lb != 0x254 && lb != 0x7f0 && lb != 0xf14)
        return 0;
    if (rd(w - 12, &t0) || rd(w - 4, &t1) || rd(w + 4, &t2))
        return 0;
    f0 = (u32)t0;
    f1 = (u32)(t0 >> 32);
    f2 = (u32)t1;
    f3 = (u32)(t1 >> 32);
    f4 = (u32)t2;
    (void)f3;
    return f0 == 0xf2fb83e9 && f1 == 0xf8696908 && f2 == 0xd63f0100 && f4 == 0x72a21148;
}

static int from_scratch(void)
{
    u64 sp, p, end, w;
    asm volatile("mov %0, sp" : "=r"(sp));
    end = (sp | 0x3fffUL) + 1 - 0x200;
    if (sp + SCAN_BYTES < end)
        end = sp + SCAN_BYTES;
    for (p = sp; p < end; p += 8) {
        w = *(volatile u64 *)p;
        if (site_match(w)) {
            last_dist = p - sp;
            return 1;
        }
    }
    return 0;
}

static void before_alloc(hook_fargs2_t *a, void *udata)
{
    void *p;
    if (a->arg0 != SCRATCH_SIZE || a->arg1 != SCRATCH_GFP)
        return;
    if (!from_scratch()) {
        n_other++;
        return;
    }
    p = vmalloc_fn(SCRATCH_SIZE);
    if (!p) {
        n_nomem++;
        return;
    }
    if (!track_add((u64)p)) {
        vfree_fn(p);
        n_nomem++;
        return;
    }
    n_scratch++;
    if (n_scratch <= 16)
        pr_info("kma-fix: scratch page -> vmalloc %llx (stack dist %llu)\n", (u64)p, last_dist);
    a->skip_origin = 1;
    a->ret = (u64)p;
}

static void before_free(hook_fargs2_t *a, void *udata)
{
    if (!a->arg0 || !track_take(a->arg0))
        return;
    vfree_fn((const void *)a->arg0);
    n_freed++;
    a->skip_origin = 1;
    a->ret = 0;
}

static void before_glp(hook_fargs3_t *a, void *udata)
{
    if (a->arg0 != init_mm_addr || !in_linear(a->arg1))
        return;
    if (linear_block(a->arg1)) {
        a->skip_origin = 1;
        a->ret = 0;
        n_guard++;
        if (n_guard <= 16)
            pr_info("kma-fix: guarded get_locked_pte on block-mapped %llx\n", a->arg1);
    }
}

static long fix_init(const char *args, const char *event, void *__user reserved)
{
    u64 tcr, a_ms, t1sz;
    hook_err_t e1, e2, e3;

    nofault = (void *)kallsyms_lookup_name("copy_from_kernel_nofault");
    vmalloc_fn = (void *)kallsyms_lookup_name("vmalloc");
    vfree_fn = (void *)kallsyms_lookup_name("vfree");
    alloc_addr = (void *)kallsyms_lookup_name("alloc_pages_exact");
    free_addr = (void *)kallsyms_lookup_name("free_pages_exact");
    glp_addr = (void *)kallsyms_lookup_name("__get_locked_pte");
    init_mm_addr = kallsyms_lookup_name("init_mm");
    a_ms = kallsyms_lookup_name("memstart_addr");
    if (!nofault || !vmalloc_fn || !vfree_fn || !alloc_addr || !free_addr || !glp_addr || !init_mm_addr || !a_ms) {
        pr_err("kma-fix: symbol lookup failed, not loaded\n");
        return -1;
    }
    if (rd(a_ms, &memstart)) {
        pr_err("kma-fix: cannot read memstart_addr\n");
        return -1;
    }
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    t1sz = (tcr >> 16) & 0x3f;
    if (t1sz != 25) {
        pr_err("kma-fix: unsupported t1sz=%llu, not loaded\n", t1sz);
        return -1;
    }
    page_offset = (u64)-1L << (64 - t1sz);
    linear_size = 1UL << (64 - t1sz - 1);
    e1 = hook_wrap3(glp_addr, before_glp, 0, 0);
    e2 = hook_wrap2(free_addr, before_free, 0, 0);
    e3 = hook_wrap2(alloc_addr, before_alloc, 0, 0);
    pr_info("kma-fix: loaded hooks glp=%d free=%d alloc=%d\n", e1, e2, e3);
    if (e1 || e2 || e3) {
        if (!e1)
            hook_unwrap(glp_addr, before_glp, 0);
        if (!e2)
            hook_unwrap(free_addr, before_free, 0);
        if (!e3)
            hook_unwrap(alloc_addr, before_alloc, 0);
        return -1;
    }
    return 0;
}

static long fix_ctl0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kma-fix: scratch=%llu other=%llu nomem=%llu freed=%llu guard=%llu live=%d\n",
            n_scratch, n_other, n_nomem, n_freed, n_guard, track_count());
    return 0;
}

static long fix_exit(void *__user reserved)
{
    int live = track_count();
    hook_unwrap(alloc_addr, before_alloc, 0);
    hook_unwrap(free_addr, before_free, 0);
    hook_unwrap(glp_addr, before_glp, 0);
    pr_info("kma-fix: unloaded scratch=%llu freed=%llu guard=%llu live=%d\n", n_scratch, n_freed, n_guard, live);
    if (live)
        pr_err("kma-fix: %d vmalloc pages still owned by KMA, reboot before next use\n", live);
    return 0;
}

KPM_INIT(fix_init);
KPM_CTL0(fix_ctl0);
KPM_EXIT(fix_exit);

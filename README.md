# kma-fix

KMA-RW-DRIVER 709.3 在 Pixel 9(内核 6.1.157)上初始化 panic 的配套补丁,独立 KPM

KMA 对线性映射页调用 `__get_locked_pte`,而该设备的线性映射多为 1GB 块映射,内核把块基址当页表读,在 `_raw_spin_lock` 崩溃。本模块:

1. `alloc_pages_exact(0x1000, 0xcc0)` 的调用者是 KMA 的暂存页调用点时,改返回 `vmalloc` 页。
2. 释放这些页时改走 `vfree`。
3. `__get_locked_pte` 遇到 `init_mm` 的块映射地址时返回 NULL。

## 构建与使用

```
git clone --recurse-submodules <repo>
make
ksud kpm load kma-fix.kpm
```

状态:`ksud kpm control kma-fix s`。

卸载顺序:先卸 KMA,再卸 kma-fix。

## 限制

- 仅验证：Pixel 9,内核 6.1.157,`kma_v6.12.709.3.kpm`。

## 许可

GPL v2。

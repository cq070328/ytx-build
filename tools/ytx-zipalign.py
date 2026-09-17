#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ytx-zipalign.py — 纯 Python APK zipalign（v2，基于 zipfile）

为什么需要（实测根因）：
  Android 11+ (targetSdk 30+) 要求：
    · resources.arsc  Stored(不压缩) + 4 字节对齐
    · native .so      Stored(不压缩) + 页对齐(4096/16384)
  apktool 回编只做「不压缩」，不做「对齐」→ 安装报：
    "requires the resources.arsc ... aligned on a 4-byte boundary"
    "extractNativeLibs=false ... Failed to extract native libraries, res=-2"

原理（可靠版）：
  用 zipfile 读条目（健壮），预演偏移量，给目标条目注入 ZIP extra
  padding 使 data 起始偏移对齐，再用 zipfile 写出（已验证 extra 生效）。

用法:
  python3 ytx-zipalign.py <in.apk> <out.apk> [--page 4096] [--all]
    --all  同时把 .so / .arsc 设为 Stored
"""

import sys
import os
import zipfile
import struct

EXTRA_ID = 0xCAFE


def align_of(name, page):
    low = name.lower()
    if low.endswith('resources.arsc'):
        return 4
    if low.endswith('.so'):
        return page
    return 0


def build_extra(pad_bytes):
    """构造长度为 pad_bytes 的合法 extra（>=4）。"""
    if pad_bytes < 4:
        return b''
    return struct.pack('<HH', EXTRA_ID, pad_bytes - 4) + b'\x00' * (pad_bytes - 4)


def zipalign(src, dst, page=4096, force_stored=True):
    zin = zipfile.ZipFile(src, 'r')
    infos = zin.infolist()

    # --- 第一步：预演偏移，计算每个条目需要的 extra len ---
    # local header 固定 30 字节；数据紧跟前一个 entry 之后
    offset = 0
    plan = []   # (info, data_bytes, extra_bytes, data_off)
    for info in infos:
        data = zin.read(info.filename)
        name_b = info.filename.encode('utf-8')
        need = align_of(info.filename, page)

        if need:
            # 目标：data_off = offset + 30 + len(name) + len(extra) 且 % need == 0
            base = offset + 30 + len(name_b)
            pad = (-base) % need
            # extra 必须是 0 或 >=4；pad 为 1..3 时补一个对齐周期
            if 0 < pad < 4:
                pad += need
            extra = build_extra(pad) if pad >= 4 else b''
        else:
            extra = b''

        data_off = offset + 30 + len(name_b) + len(extra)
        plan.append((info, data, extra, data_off, name_b))
        # 数据大小：Stored 时 = len(data)；压缩时用压缩后大小（此处若重写需重压）
        # 为简化，本工具对所有条目保持其原压缩方式；若 force_stored 且目标条目需对齐，则 Stored
        csize = len(data) if (force_stored and need) else info.compress_size
        if force_stored and need:
            csize = len(data)
        offset = data_off + csize

    zin.close()

    # --- 第二步：写出 ---
    zout = zipfile.ZipFile(dst, 'w')
    for info, data, extra, data_off, name_b in plan:
        need = align_of(info.filename, page)
        zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        zi.external_attr = info.external_attr
        zi.internal_attr = info.internal_attr
        zi.create_system = info.create_system

        if need and force_stored:
            zi.compress_type = zipfile.ZIP_STORED
        else:
            zi.compress_type = info.compress_type

        # 注入对齐 padding
        # ⚠️ zipfile 会把 extra 原样写出，但**可能截断**（若含非法结构）
        #    我们只保留我们自己的 extra（丢弃原 extra 可能带来风险）
        zi.extra = extra

        zout.writestr(zi, data)
    zout.close()
    return len(plan)


def main():
    if len(sys.argv) < 3:
        print("用法: ytx-zipalign.py <in.apk> <out.apk> [--page N]")
        return 1
    src, dst = sys.argv[1], sys.argv[2]
    page = 4096
    if '--page' in sys.argv:
        try:
            page = int(sys.argv[sys.argv.index('--page') + 1])
        except Exception:
            pass
    if not os.path.exists(src):
        print("❌ 不存在: " + src)
        return 1
    n = zipalign(src, dst, page)
    print("✅ 已处理 %d 条目 (page=%d) -> %s" % (n, page, dst))
    return 0


if __name__ == '__main__':
    sys.exit(main())
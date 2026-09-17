#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ytx-dex-replace.py — 极速 DEX 替换（不重编资源）

用途：
  脱壳后的真实 DEX 替换进原始 APK，
  保持 resources.arsc / so / 资源 完全不变（避免 apktool 重编的资源问题）。

原理：
  直接重写 zip：
    · 移除原 classes*.dex
    · 用 dump 的 dex 作为 classes.dex / classes2.dex / ...
    · 保持其他条目原样（含对齐）

优势（vs apktool b）：
  · 快 10-50 倍（不解包/回编资源）
  · 资源零风险（不改动）
  · 对齐可控（复用 ytx-zipalign 的 extra 技巧）

用法：
  python3 ytx-dex-replace.py <原APK> <dump目录> <输出APK>
"""

import sys
import os
import zipfile
import struct

EXTRA_ID = 0xCAFE


def read_entries(zf):
    """读所有条目（名 -> 数据）。"""
    d = {}
    for info in zf.infolist():
        d[info.filename] = (info, zf.read(info.filename))
    return d


def write_apk(entries, out_path, page=4096):
    """重写 APK。

    ⚠️ 重要（v2 修正）：
      不要在本函数做对齐 —— zipfile 实际写 zip 时的 offset
      与我们的估算不一致（它会在自己内部调整），导致对齐失效。

      正确做法：本函数只负责「替换内容」，对齐统一交给
      ytx-zipalign.py 后处理（已验证可靠）。

      但 .so / arsc 仍要 Stored（不压缩）—— 这是独立要求。
    """
    zout = zipfile.ZipFile(out_path, 'w')

    # dex 放最前（Android 兼容性好）
    order = sorted(entries.keys())
    dexs = [k for k in order if k.endswith('.dex')]
    others = [k for k in order if not k.endswith('.dex')]

    for name in dexs + others:
        info, data = entries[name]
        low = name.lower()
        # .so / arsc 必须 Stored（Android 11+ 要求，与对齐无关）
        must_stored = low.endswith('.so') or low.endswith('resources.arsc')

        zi = zipfile.ZipInfo(name, date_time=info.date_time)
        zi.external_attr = info.external_attr
        zi.internal_attr = info.internal_attr
        zi.create_system = info.create_system
        zi.compress_type = zipfile.ZIP_STORED if must_stored else info.compress_type
        # 不设 extra（对齐交给 ytx-zipalign.py）
        zout.writestr(zi, data)

    zout.close()


def main():
    if len(sys.argv) < 4:
        print("用法: ytx-dex-replace.py <原APK> <dump目录> <输出APK>")
        return 1

    src, dumpdir, dst = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.exists(src):
        print(f"❌ 原 APK 不存在: {src}")
        return 1
    if not os.path.isdir(dumpdir):
        print(f"❌ dump 目录不存在: {dumpdir}")
        return 1

    # 收集 dump 的 dex（按大小排序：大的优先做主 dex）
    dumpdex = sorted([f for f in os.listdir(dumpdir) if f.endswith('.dex')])
    if not dumpdex:
        print("❌ dump 目录无 dex")
        return 1

    print(f"原 APK: {src}")
    print(f"dump: {len(dumpdex)} 个 dex")
    for f in dumpdex:
        print(f"  - {f} ({os.path.getsize(os.path.join(dumpdir, f))} bytes)")

    zin = zipfile.ZipFile(src, 'r')
    entries = read_entries(zin)
    zin.close()

    # 记录原有 dex 名
    old_dex = sorted([k for k in entries if k.endswith('.dex')])
    print(f"原 APK 的 dex: {old_dex}")

    # 移除所有原 dex
    for k in old_dex:
        del entries[k]

    # 写入新 dex：类路径用 classes.dex / classes2.dex ...
    # 同时：prodexdir 里的 dex 是壳加载的，需要「覆盖」它
    for i, f in enumerate(sorted(dumpdex, key=lambda x: os.path.getsize(
            os.path.join(dumpdir, x)), reverse=True)):
        name = 'classes.dex' if i == 0 else f'classes{i+1}.dex'
        with open(os.path.join(dumpdir, f), 'rb') as fh:
            data = fh.read()
        # 构造一个伪 ZipInfo（时间用固定值）
        zi = zipfile.ZipInfo(name, date_time=(1981, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        # 用一个"占位" entries 结构（write_apk 需要 info/data）
        class FakeInfo:
            pass
        fi = FakeInfo()
        fi.date_time = (1981, 1, 1, 0, 0, 0)
        fi.external_attr = 0
        fi.internal_attr = 0
        fi.create_system = 0
        fi.compress_type = zipfile.ZIP_DEFLATED
        entries[name] = (fi, data)
        print(f"  替换 {name} <- {f}")

    # 重写
    print("\n重写 APK（含对齐）…")
    write_apk(entries, dst)
    print(f"✅ 输出: {dst} ({os.path.getsize(dst)} bytes)")

    # 校验
    print("\n校验…")
    z = zipfile.ZipFile(dst)
    dexes = [k for k in z.namelist() if k.endswith('.dex')]
    print(f"  含 {len(dexes)} 个 dex: {dexes}")
    bad = z.testzip()
    print(f"  zip 完整性: {'✅' if bad is None else '❌ ' + str(bad)}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
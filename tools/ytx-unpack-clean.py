#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ytx-unpack-clean.py — 云脱修 · 去壳清理器

职责：脱壳后，清除壳的特征 + 还原真实入口，让 APK 能独立运行。

支持能力：
  ① 入口替换（Application → 真实类）
  ② 壳 so 删除（360/乐固/梆梆/爱加密/SecShell/NMMP/...）
  ③ 壳 assets 清理
  ④ 壳 stub 类清理（可选，需 dex 反编）

用法：
  python3 ytx-unpack-clean.py <输入APK> <输出APK> [--real-app <类名>] [--dry-run]

若不指定 --real-app，会自动从「APK 内的 dex」或「dump 目录」搜索。
"""

import sys
import os
import re
import zipfile
import shutil

# ============================================================
# 壳特征库（按厂商）
# ============================================================
SHELL_SIGNS = {
    '360': {
        'so': ['libjiagu.so', 'libjiagu_art.so', 'libjiagu_x86.so', 'libjiagu_a64.so'],
        'entry': ['com.stub.StubApp', 'com.qihoo.util.StubApplication'],
        'assets': ['libjiagu', 'libjiagu.so'],
    },
    'Tencent(乐固)': {
        'so': ['libshell.so', 'libshellx.so', 'libtup.so', 'libtxgui.so'],
        'entry': ['com.tencent.StubShell.TxAppEntry', 'com.tencent.bugly.legu.LeguApp'],
        'assets': ['0OO00l111l1l', 'o0oooOO0ooOo.dat'],
    },
    'Bangcle(梆梆)': {
        'so': ['libsecexe.so', 'libsecmain.so', 'libDexHelper.so'],
        'entry': ['com.secneo.apkwrapper.ApplicationWrapper'],
        'assets': ['libsecexe', 'libsecmain'],
    },
    'Bangbang(梆梆企业)': {
        'so': ['libDexHelper.so', 'libDexHelper-x86.so'],
        'entry': ['com.bangcle.protect.BcApplication'],
        'assets': [],
    },
    'IJiami(爱加密)': {
        'so': ['libexec.so', 'libexecmain.so', 'libijiami.so'],
        'entry': ['com.ijiami.O0oO0OooOoo', 's.h.e.l.l.S'],
        'assets': ['ijiami.dat', 'ijiami.ajm'],
    },
    'SecShell': {
        'so': [],
        'so_prefix': ['libshell-', 'libshella-'],
        'entry': ['MyWrapperProxyApplication', 'SecShellApplication'],
        'assets': ['fsapk'],
    },
    'NMMP': {
        'so': ['libnmmp.so', 'libnmmvm.so'],
        'entry': [],
        'assets': [],
    },
    'Legu(阿里)': {
        'so': ['libmobisec.so', 'libmobisecx.so'],
        'entry': ['com.ali.mobisecenhance.StubApplication'],
        'assets': [],
    },
    'Naga': {
        'so': ['libchaosvmp.so', 'libddog.so', 'libfdog.so'],
        'entry': ['com.nagain.LibProtect'],
        'assets': [],
    },
}


def detect_shell(zf):
    """检测壳类型（返回 (name, matched_so, matched_entry))。"""
    names = [n for n in zf.namelist()]
    names_lower = [n.lower() for n in names]

    for shell, signs in SHELL_SIGNS.items():
        hit_so = []
        # 精确 so 匹配
        for so in signs.get('so', []):
            for n in names_lower:
                if n.endswith(so.lower()):
                    hit_so.append(n)
        # 前缀 so 匹配（如 SecShell 的 libshell-*）
        for pre in signs.get('so_prefix', []):
            for n in names_lower:
                bn = n.split('/')[-1]
                if bn.startswith(pre.lower()) and bn.endswith('.so'):
                    hit_so.append(n)
        if hit_so:
            return shell, sorted(set(hit_so)), signs
    return None, [], {}


def find_real_application(zf, extra_dirs=None, manifest_text=None):
    """从 manifest / dex 里找真实 Application 类名。

    优先：
      1. manifest 里其他可疑入口（非壳）
      2. dex 里 extends Application 的类
    """
    # 1. 从 dex 里找（扫描所有 classes*.dex）
    candidates = []
    for name in zf.namelist():
        if not name.endswith('.dex'):
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        # 简易字符串扫描（找 **Application 形式的类名）
        text = data.decode('latin-1', 'ignore')
        for m in re.finditer(r'L([a-zA-Z][a-zA-Z0-9/_]*Application);', text):
            cls = m.group(1)
            # 排除系统类
            if cls.startswith('android/') or cls.startswith('androidx/'):
                continue
            if cls.startswith('java/'):
                continue
            # 排除知名的壳类
            is_shell = False
            for s in SHELL_SIGNS.values():
                for e in s.get('entry', []):
                    if cls in e.replace('.', '/'):
                        is_shell = True
            if not is_shell:
                candidates.append(cls)

    # 2. 扫外部目录（dump 的 dex）
    for d in (extra_dirs or []):
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.endswith('.dex'):
                continue
            try:
                text = open(os.path.join(d, f), 'rb').read().decode('latin-1', 'ignore')
            except Exception:
                continue
            for m in re.finditer(r'L([a-zA-Z][a-zA-Z0-9/_]*Application);', text):
                cls = m.group(1)
                if cls.startswith(('android/', 'androidx/', 'java/')):
                    continue
                candidates.append(cls)

    # 去重 + 排序（优先含 app / my / main 的）
    seen = set()
    uniq = []
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        uniq.append(c)

    def score(c):
        low = c.lower()
        s = 0
        if 'app' in low: s += 3
        if 'my' in low: s += 2
        if 'main' in low: s += 2
        if 'base' in low: s -= 1
        return s
    uniq.sort(key=score, reverse=True)
    return uniq


def clean_apk(src, dst, real_app=None, dry_run=False, dump_dir=None):
    zf = zipfile.ZipFile(src, 'r')

    print(f"输入: {src} ({os.path.getsize(src)} bytes)")
    print()

    # 1. 检测壳
    shell, hit_so, signs = detect_shell(zf)
    if shell:
        print(f"[检测] 壳类型: {shell}")
        print(f"       壳 so: {hit_so}")
    else:
        print("[检测] 未匹配已知壳特征")
        signs = {}

    # 2. 找真实 Application
    #   ⚠️ 关键：优先从 dump 目录找（壳 APK 的 dex 里只有壳类！）
    if not real_app:
        search_dirs = []
        if dump_dir:
            search_dirs.append(dump_dir)
        # 从 dump 里找（若指定）
        cands = []
        if search_dirs:
            cands = find_real_application(zf, extra_dirs=search_dirs)
            # 过滤掉壳类
            shell_entries = []
            for s in SHELL_SIGNS.values():
                shell_entries.extend(s.get('entry', []))
            cands = [c for c in cands
                     if not any(se.replace('.', '/') in c for se in shell_entries)]
        if not cands:
            # 回退：从 APK 自身 dex 找
            cands = find_real_application(zf)

        if cands:
            real_app = cands[0]
            print(f"[入口] 自动推断真实 Application: {real_app}")
            print(f"       候选: {cands[:5]}")
        else:
            print("[入口] ⚠️ 未能自动找到真实 Application（需手动 --real-app）")
    else:
        print(f"[入口] 指定真实 Application: {real_app}")

    # 3. 要删除的条目
    to_delete = set()
    for n in zf.namelist():
        nl = n.lower()
        for so in signs.get('so', []):
            if nl.endswith(so.lower()):
                to_delete.add(n)
        for pre in signs.get('so_prefix', []):
            bn = nl.split('/')[-1]
            if bn.startswith(pre.lower()) and bn.endswith('.so'):
                to_delete.add(n)
        for a in signs.get('assets', []):
            if a.lower() in nl:
                to_delete.add(n)

    print()
    print(f"[清理] 待删除 {len(to_delete)} 个条目:")
    for n in sorted(to_delete)[:20]:
        print(f"        - {n}")

    if dry_run:
        print()
        print("[dry-run] 不实际写入")
        zf.close()
        return 0

    # 4. 重写 APK（删除壳条目）
    zout = zipfile.ZipFile(dst, 'w')
    for info in zf.infolist():
        if info.filename in to_delete:
            continue
        data = zf.read(info.filename)
        low = info.filename.lower()
        must_stored = low.endswith('.so') or low.endswith('resources.arsc')

        zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        zi.external_attr = info.external_attr
        zi.internal_attr = info.internal_attr
        zi.create_system = info.create_system
        zi.compress_type = zipfile.ZIP_STORED if must_stored else info.compress_type
        zout.writestr(zi, data)
    zout.close()
    zf.close()

    print()
    print(f"✅ 已清理壳特征 -> {dst} ({os.path.getsize(dst)} bytes)")
    if real_app:
        print()
        print(f"⚠️ 还需改 Manifest 的 application:name → {real_app.replace('/', '.')}")
        print(f"    （或用 ytx_patch_manifest.py / apktool 处理）")
    return 0


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print("用法: ytx-unpack-clean.py <输入APK> <输出APK> "
              "[--real-app <类名>] [--dump-dir <目录>] [--dry-run]")
        return 1

    src, dst = args[0], args[1]
    real_app = None
    dump_dir = None
    dry_run = False
    if '--real-app' in args:
        i = args.index('--real-app')
        if i + 1 < len(args):
            real_app = args[i + 1]
    if '--dump-dir' in args:
        i = args.index('--dump-dir')
        if i + 1 < len(args):
            dump_dir = args[i + 1]
    if '--dry-run' in args:
        dry_run = True

    if not os.path.exists(src):
        print(f"❌ 不存在: {src}")
        return 1
    return clean_apk(src, dst, real_app, dry_run, dump_dir)


if __name__ == '__main__':
    sys.exit(main())
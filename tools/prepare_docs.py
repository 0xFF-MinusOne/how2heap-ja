#!/usr/bin/env python3
"""ビルド用に Markdown を .site-src/ へコピーする。元のファイルは変更しない。
サイトに載せないファイル(ソースコードなど)への相対リンクは、GitHub 上のファイルへのリンクに書き換える。"""
import posixpath
import re
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent.parent
out = root / ".site-src"
REPO = "https://github.com/0xFF-MinusOne/" + root.name
IMAGES = {".png", ".jpg", ".jpeg", ".gif", ".svg"}

if out.exists():
    shutil.rmtree(out)
out.mkdir()

pages = {p.name for p in root.glob("*.md")}
LINK = re.compile(r"(!?\[[^\]]*\])\(([^)\s]+)((?:\s+\"[^\"]*\")?)\)")


def rewrite(m):
    label, target, title = m.group(1), m.group(2), m.group(3)
    if re.match(r"^([a-z][a-z0-9+.-]*:|#|/)", target, re.I):
        return m.group(0)
    path, _, frag = target.partition("#")
    path = posixpath.normpath(path)
    full = root / path
    if path in pages:
        return m.group(0)
    if not full.exists():
        return m.group(0)
    if full.suffix.lower() in IMAGES and label.startswith("!"):
        dst = out / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(full, dst)
        return m.group(0)
    kind = "tree" if full.is_dir() else "blob"
    url = f"{REPO}/{kind}/main/{path}" + (f"#{frag}" if frag else "")
    return f"{label}({url}{title})"


for p in sorted(root.glob("*.md")):
    text = p.read_text(encoding="utf-8")
    (out / p.name).write_text(LINK.sub(rewrite, text), encoding="utf-8")
print(f"prepared {sum(1 for _ in out.rglob('*') if _.is_file())} files in {out}")

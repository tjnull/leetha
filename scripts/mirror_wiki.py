#!/usr/bin/env python3
"""Mirror docs/wiki/ into the GitHub wiki repository.

The in-repo docs are the source of truth; the GitHub wiki is a published copy.
A straight file copy would ship broken links, because the two render links
differently:

* Wiki page URLs have no ``.md`` -- ``[x](Device-Authorization.md)`` resolves to
  ``/wiki/Device-Authorization.md``, which 404s.
* Relative links into the source tree (``../../src/...``) have no meaning from
  the wiki, which is a separate repository.

Both are rewritten here.

Usage::

    python scripts/mirror_wiki.py --dry-run     # show what would change
    python scripts/mirror_wiki.py --push        # clone, sync, commit, push

The wiki must already be initialised: GitHub only creates ``<repo>.wiki.git``
after the first page is created through the web UI.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "tjnull/leetha"
WIKI_REMOTE = f"https://github.com/{REPO}.wiki.git"
BLOB_BASE = f"https://github.com/{REPO}/blob/main"

SOURCE = Path(__file__).resolve().parent.parent / "docs" / "wiki"

_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def rewrite_links(text: str) -> str:
    """Rewrite in-repo link forms into their GitHub-wiki equivalents."""

    def fix(match: re.Match) -> str:
        label, target = match.group(1), match.group(2)

        if target.startswith(("http://", "https://", "#", "mailto:")):
            return match.group(0)

        # Relative link into the source tree -> absolute blob URL.
        if target.startswith("../"):
            cleaned = target.lstrip("./")
            while cleaned.startswith("../"):
                cleaned = cleaned[3:]
            return f"[{label}]({BLOB_BASE}/{cleaned})"

        # Wiki page link -> drop the .md, keep any anchor.
        if target.endswith(".md") or ".md#" in target:
            page, _, anchor = target.partition("#")
            page = page[:-3] if page.endswith(".md") else page
            return f"[{label}]({page}#{anchor})" if anchor else f"[{label}]({page})"

        return match.group(0)

    return _LINK.sub(fix, text)


def render() -> dict[str, str]:
    """Return {filename: wiki-ready content} for every source page."""
    return {p.name: rewrite_links(p.read_text(encoding="utf-8"))
            for p in sorted(SOURCE.glob("*.md"))}


def run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"$ {' '.join(cmd)}\n{result.stderr.strip()}")
    return result.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--push", action="store_true", help="clone, sync and push")
    ap.add_argument("--dry-run", action="store_true", help="show the rewrites only")
    args = ap.parse_args()

    pages = render()
    if not pages:
        raise SystemExit(f"no pages found in {SOURCE}")

    if not args.push or args.dry_run:
        changed = 0
        for name, content in pages.items():
            original = (SOURCE / name).read_text(encoding="utf-8")
            if content != original:
                changed += 1
                before = set(_LINK.findall(original))
                after = set(_LINK.findall(content))
                for label, target in sorted(before - after):
                    new = dict(after).get(label, "?")
                    print(f"  {name}: [{label}]({target}) -> ({new})")
        print(f"\n{len(pages)} page(s), {changed} needing link rewrites")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        clone = Path(tmp) / "wiki"
        print(f"cloning {WIKI_REMOTE}")
        try:
            run(["git", "clone", "--depth", "1", WIKI_REMOTE, str(clone)])
        except SystemExit as exc:
            print(exc, file=sys.stderr)
            print(
                "\nThe wiki does not exist yet. GitHub creates it only after the\n"
                f"first page is made in the browser: https://github.com/{REPO}/wiki",
                file=sys.stderr,
            )
            return 1

        for stale in clone.glob("*.md"):
            stale.unlink()
        for name, content in pages.items():
            (clone / name).write_text(content, encoding="utf-8")

        if not run(["git", "status", "--porcelain"], cwd=clone).strip():
            print("wiki already up to date")
            return 0

        run(["git", "add", "-A"], cwd=clone)
        run(["git", "commit", "-m", "docs: sync wiki from docs/wiki/"], cwd=clone)
        run(["git", "push"], cwd=clone)
        print(f"pushed {len(pages)} page(s) to the wiki")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

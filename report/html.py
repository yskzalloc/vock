"""Generate coverage.html from resolved source coverage."""
import html as html_mod
from pathlib import Path


def generate(cov: dict[str, set[int]], kernel_src: str,
             before: int, after: int, output_path: str, filter_kw: str = None):
    """Write coverage.html with highlighted source lines."""
    src_root = Path(kernel_src)
    out = []
    out.append("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>vock coverage</title>
<style>
body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
h1 { color: #569cd6; } h2 { color: #dcdcaa; margin-top: 2em; }
.cov { background: #1e3a1e; color: #4ec9b0; }
.ctx { color: #808080; } .sep { color: #569cd6; }
.ln { color: #858585; display: inline-block; width: 5em; text-align: right; margin-right: 1em; }
pre { margin: 0; } .summary { color: #9cdcfe; margin-bottom: 2em; }
</style></head><body>
<h1>vock kernel coverage report</h1>
""")

    total_files = 0
    total_lines = 0
    for fpath, covered in sorted(cov.items()):
        if filter_kw and filter_kw not in fpath:
            continue
        total_files += 1
        total_lines += len(covered)
        out.append(f'<h2>{html_mod.escape(fpath)} ({len(covered)} lines)</h2>\n<pre>')

        full = src_root / fpath
        try:
            all_lines = full.read_text(errors="ignore").splitlines()
        except FileNotFoundError:
            out.append('  (file not found)\n</pre>')
            continue

        show = set()
        for ln in covered:
            for i in range(max(1, ln - before), min(len(all_lines), ln + after) + 1):
                show.add(i)

        last = -1
        for ln in sorted(show):
            if ln != last + 1:
                out.append('<span class="sep">   ...</span>\n')
            content = html_mod.escape(all_lines[ln - 1]) if ln <= len(all_lines) else ""
            cls = "cov" if ln in covered else "ctx"
            mark = "&gt;" if ln in covered else "|"
            out.append(f'<span class="{cls}"><span class="ln">{ln}</span> {mark} {content}</span>\n')
            last = ln
        out.append('</pre>\n')

    out.insert(2, f'<p class="summary">{total_files} files, {total_lines} covered lines</p>\n')
    out.append("</body></html>")

    with open(output_path, "w") as f:
        f.writelines(out)

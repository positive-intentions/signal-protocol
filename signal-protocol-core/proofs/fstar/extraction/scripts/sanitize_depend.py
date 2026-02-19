#!/usr/bin/env python3
import sys
from pathlib import Path

def sanitize(src: Path, dst: Path) -> None:
    data = src.read_text()
    blocks = [b for b in data.split('\n\n') if b.strip()]
    out_lines = []
    for b in blocks:
        lines = b.splitlines()
        header = lines[0]
        target = header.split(':',1)[0].strip()
        deps = []
        seen = set()
        for ln in lines[1:]:
            dep = ln.rstrip(' \\\\').strip()
            if not dep:
                continue
            # skip self-dependency
            if dep == target:
                continue
            if dep in seen:
                continue
            seen.add(dep)
            deps.append(ln)
        out_lines.append(header)
        out_lines.extend(deps)
        out_lines.append('')
    dst.write_text('\n'.join(out_lines))

def main():
    if len(sys.argv) != 3:
        print('Usage: sanitize_depend.py <src.tmp> <dst>', file=sys.stderr)
        sys.exit(2)
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    sanitize(src, dst)

if __name__ == '__main__':
    main()

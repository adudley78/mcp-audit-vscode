"""
Generate PNG icon assets from inline SVG sources.
Requires: cairosvg (pip install cairosvg)
Output: images/icon.png, icon-32.png, icon-16.png, icon-light-16.png
"""
import os
import sys
import tempfile

try:
    import cairosvg
except ImportError:
    sys.exit("cairosvg is required: pip install cairosvg")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES_DIR = os.path.join(REPO_ROOT, "images")
os.makedirs(IMAGES_DIR, exist_ok=True)

SVG_DARK = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
    <rect width="100%" height="100%" fill="#0B1120" rx="16"/>
    <g transform="translate(10, 0)">
        <path d="M20,108 L20,20 L44,20 L64,60 L84,20 L108,20 L108,108 L88,108 L88,48 L64,92 L40,48 L40,108 Z" fill="#FFFFFF"/>
        <path d="M12,88 L116,36 L116,48 L12,100 Z" fill="#00C9B1"/>
        <circle cx="64" cy="66" r="7" fill="#C0392B"/>
    </g>
</svg>
"""

SVG_LIGHT = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
    <g transform="translate(10, 0)">
        <path d="M20,108 L20,20 L44,20 L64,60 L84,20 L108,20 L108,108 L88,108 L88,48 L64,92 L40,48 L40,108 Z" fill="#0B1120"/>
        <path d="M12,88 L116,36 L116,48 L12,100 Z" fill="#00C9B1"/>
        <circle cx="64" cy="66" r="7" fill="#C0392B"/>
    </g>
</svg>
"""

TARGETS = [
    # (svg_content, output_filename, width, height)
    (SVG_DARK,  "icon.png",         128, 128),
    (SVG_DARK,  "icon-32.png",       32,  32),
    (SVG_DARK,  "icon-16.png",       16,  16),
    (SVG_LIGHT, "icon-light-16.png", 16,  16),
]

for svg_content, filename, w, h in TARGETS:
    out_path = os.path.join(IMAGES_DIR, filename)
    with tempfile.NamedTemporaryFile(suffix=".svg", mode="w", delete=False) as tmp:
        tmp.write(svg_content)
        tmp_path = tmp.name
    try:
        cairosvg.svg2png(
            url=tmp_path,
            write_to=out_path,
            output_width=w,
            output_height=h,
        )
    finally:
        os.unlink(tmp_path)
    size = os.path.getsize(out_path)
    print(f"  {filename:25s}  {w}x{h}  {size:>6d} bytes")

print("\nDone — all icons written to images/")

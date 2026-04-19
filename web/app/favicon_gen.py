"""Genera favicon.ico (multi-size) y favicon.svg con la marca MonitorMaat.
Ejecutado al startup; idempotente — si los archivos ya existen, no hace nada."""
from pathlib import Path
from PIL import Image, ImageDraw


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def _gradient_rgba(size: int) -> Image.Image:
    """Gradiente diagonal cyan -> púrpura -> rosa con esquinas redondeadas."""
    c1 = (0x22, 0xd3, 0xee)   # cyan
    c2 = (0xa8, 0x55, 0xf7)   # púrpura
    c3 = (0xf4, 0x3f, 0x5e)   # rosa
    pixels = bytearray()
    for y in range(size):
        for x in range(size):
            t = (x + y) / max(1, 2 * (size - 1))
            if t < 0.5:
                k = t / 0.5
                r = _lerp(c1[0], c2[0], k)
                g = _lerp(c1[1], c2[1], k)
                b = _lerp(c1[2], c2[2], k)
            else:
                k = (t - 0.5) / 0.5
                r = _lerp(c2[0], c3[0], k)
                g = _lerp(c2[1], c3[1], k)
                b = _lerp(c2[2], c3[2], k)
            pixels.extend((r, g, b, 255))
    img = Image.frombytes("RGBA", (size, size), bytes(pixels))

    # Mascara redondeada
    radius = max(2, size // 5)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size, size), radius=radius, fill=255)
    img.putalpha(mask)
    return img


def _draw_overlay(img: Image.Image) -> None:
    size = img.size[0]
    d = ImageDraw.Draw(img)
    cx = cy = size / 2

    def ring(r_frac: float, w_frac: float, alpha: int):
        r = size * r_frac
        d.ellipse(
            (cx - r, cy - r, cx + r, cy + r),
            outline=(255, 255, 255, alpha),
            width=max(2, int(size * w_frac)),
        )

    def disc(x: float, y: float, r_frac: float, alpha: int = 255):
        r = size * r_frac
        d.ellipse((x - r, y - r, x + r, y + r), fill=(255, 255, 255, alpha))

    ring(0.34, 0.025, 235)
    ring(0.22, 0.020, 175)
    disc(cx, cy, 0.10)
    disc(cx, cy - size * 0.42, 0.05)
    disc(cx + size * 0.42, cy, 0.05)
    disc(cx, cy + size * 0.42, 0.05)
    disc(cx - size * 0.42, cy, 0.05)


def make_icon(size: int = 256) -> Image.Image:
    img = _gradient_rgba(size)
    _draw_overlay(img)
    return img


SVG_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%"  stop-color="#22d3ee"/>
      <stop offset="50%" stop-color="#a855f7"/>
      <stop offset="100%" stop-color="#f43f5e"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="13" fill="url(#bg)"/>
  <circle cx="32" cy="32" r="22" stroke="#fff" stroke-width="2" fill="none" opacity=".95"/>
  <circle cx="32" cy="32" r="14" stroke="#fff" stroke-width="1.6" fill="none" opacity=".7"/>
  <circle cx="32" cy="32" r="6.5" fill="#fff"/>
  <circle cx="32" cy="5"  r="3" fill="#fff"/>
  <circle cx="59" cy="32" r="3" fill="#fff"/>
  <circle cx="32" cy="59" r="3" fill="#fff"/>
  <circle cx="5"  cy="32" r="3" fill="#fff"/>
</svg>
"""


def ensure_favicons(static_dir: Path) -> None:
    static_dir.mkdir(parents=True, exist_ok=True)
    ico_path = static_dir / "favicon.ico"
    svg_path = static_dir / "favicon.svg"
    png_path = static_dir / "favicon-256.png"

    if not svg_path.exists():
        svg_path.write_text(SVG_TEMPLATE, encoding="utf-8")

    if not ico_path.exists():
        base = make_icon(256)
        sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        scaled = [base.resize(s, Image.LANCZOS) for s in sizes]
        scaled[-1].save(
            ico_path,
            format="ICO",
            sizes=sizes,
            append_images=scaled[:-1],
        )
        base.save(png_path, format="PNG")

"""Genera demiurge.ico (ojo rojo de pupila vertical) en todos los tamaños de Windows.
Misma geometría que el SVG de la interfaz (viewBox 32x32). Uso: python make_icon.py"""
from pathlib import Path
from PIL import Image, ImageDraw

S = 1024            # lienzo de trabajo (supersampling)
K = S / 32          # escala desde el viewBox 32x32
BLOOD = (209, 26, 42, 255)
VOID = (10, 7, 7, 255)
BONE = (237, 229, 227, 255)


def quad(p0, c, p1, n=200):
    return [((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * c[0] + t * t * p1[0],
             (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * c[1] + t * t * p1[1]) for t in (i / n for i in range(n + 1))]


def sc(points):
    return [(x * K, y * K) for x, y in points]


# Almendra: M1.5 16 Q16 1 30.5 16 Q16 31 1.5 16 Z
almond = sc(quad((1.5, 16), (16, 1), (30.5, 16)) + quad((30.5, 16), (16, 31), (1.5, 16)))

def shrink(points, stroke):
    """Almendra interior: escala hacia el centro (16,16) para dejar un borde de `stroke` unidades."""
    sx = (14.5 - stroke) / 14.5
    sy = (7.5 - stroke) / 7.5
    return [(16 * K + (x - 16 * K) * sx, 16 * K + (y - 16 * K) * sy) for x, y in points]


# Borde limpio: almendra roja y, encima, una almendra negra más chica (en vez de trazar una línea gruesa).
STROKE = 1.15
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.polygon(almond, fill=BLOOD)
almond_in = shrink(almond, STROKE)
d.polygon(almond_in, fill=VOID)

# Iris, pupila y brillo, recortados a la almendra interior.
inner = Image.new("RGBA", (S, S), (0, 0, 0, 0))
di = ImageDraw.Draw(inner)
r = 6.2 * K
di.ellipse((16 * K - r, 16 * K - r, 16 * K + r, 16 * K + r), fill=BLOOD)
di.ellipse((16 * K - 1.4 * K, 16 * K - 5 * K, 16 * K + 1.4 * K, 16 * K + 5 * K), fill=VOID)
di.ellipse((18.3 * K - 1 * K, 13.6 * K - 1 * K, 18.3 * K + 1 * K, 13.6 * K + 1 * K), fill=BONE)
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).polygon(almond_in, fill=255)
img.paste(inner, (0, 0), Image.composite(inner, Image.new("RGBA", (S, S)), mask).split()[3])

out = Path(__file__).with_name("demiurge.ico")
sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]
img.save(out, sizes=sizes)
img.resize((256, 256), Image.LANCZOS).save(out.with_name("demiurge-256.png"))
print("ok", out)

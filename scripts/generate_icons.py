from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
CANVAS = 1024


def build_icon() -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Dark application tile with a bright border remains legible at 16x16.
    draw.rounded_rectangle(
        (48, 48, 976, 976),
        radius=220,
        fill="#0f172a",
        outline="#60a5fa",
        width=34,
    )
    draw.ellipse((118, 118, 906, 906), fill="#172554", outline="#2563eb", width=22)

    # Network longitude/latitude lines.
    draw.ellipse((222, 222, 802, 802), outline="#38bdf8", width=24)
    draw.arc((355, 222, 669, 802), 80, 280, fill="#38bdf8", width=20)
    draw.arc((355, 222, 669, 802), 260, 100, fill="#38bdf8", width=20)
    draw.arc((222, 352, 802, 672), 5, 175, fill="#38bdf8", width=18)
    draw.arc((222, 352, 802, 672), 185, 355, fill="#38bdf8", width=18)

    # Shield overlay.
    shield = [(512, 202), (748, 302), (714, 655), (512, 824), (310, 655), (276, 302)]
    draw.polygon(shield, fill="#2563eb", outline="#bfdbfe", width=26)
    inner = [(512, 259), (688, 334), (663, 622), (512, 751), (361, 622), (336, 334)]
    draw.polygon(inner, fill="#1d4ed8")

    # Geometric K mark; no font dependency.
    draw.rounded_rectangle((438, 354, 495, 652), radius=26, fill="white")
    draw.line((485, 507, 610, 380), fill="white", width=58)
    draw.line((485, 505, 624, 650), fill="white", width=58)

    # Green verified badge.
    draw.ellipse((682, 672, 902, 892), fill="#16a34a", outline="white", width=22)
    draw.line((735, 782, 790, 833), fill="white", width=28)
    draw.line((786, 833, 858, 738), fill="white", width=28)
    return image


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    master = build_icon()
    resampling = Image.Resampling.LANCZOS
    master.resize((512, 512), resampling).save(ASSETS / "kiro-ip-guard.png", "PNG")
    master.resize((64, 64), resampling).save(ASSETS / "kiro-ip-guard-64.png", "PNG")
    master.save(
        ASSETS / "kiro-ip-guard.ico",
        "ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    master.save(ASSETS / "kiro-ip-guard.icns", "ICNS")
    print("Generated:")
    for path in sorted(ASSETS.glob("kiro-ip-guard*")):
        print(f"  {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

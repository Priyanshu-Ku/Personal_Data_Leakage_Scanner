"""Create a harmless JPEG containing synthetic EXIF metadata for the LA-2 demo."""
from fractions import Fraction
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = Path(__file__).resolve().parent
OUTPUT = BASE_DIR / "samples" / "demo_photo_with_metadata.jpg"


def dms(value: float):
    degrees = int(value)
    minutes_float = (value - degrees) * 60
    minutes = int(minutes_float)
    seconds = (minutes_float - minutes) * 60
    return (Fraction(degrees, 1), Fraction(minutes, 1), Fraction(round(seconds * 10000), 10000))


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (1200, 700), (235, 241, 250))
    draw = ImageDraw.Draw(image)
    try:
        title_font = ImageFont.truetype("arial.ttf", 48)
        body_font = ImageFont.truetype("arial.ttf", 28)
    except OSError:
        title_font = ImageFont.load_default()
        body_font = ImageFont.load_default()
    draw.rounded_rectangle((65, 65, 1135, 635), radius=34, fill=(255, 255, 255), outline=(45, 65, 120), width=5)
    draw.text((120, 190), "PERSONAL DATA LEAKAGE SCANNER", font=title_font, fill=(30, 50, 105))
    draw.text((120, 290), "SYNTHETIC TEST IMAGE", font=body_font, fill=(175, 75, 35))
    draw.text((120, 360), "Contains deliberately added sample EXIF fields", font=body_font, fill=(65, 75, 95))
    draw.text((120, 430), "No real personal data is used in this demonstration.", font=body_font, fill=(65, 75, 95))

    exif = Image.Exif()
    exif[271] = "DemoCam"                         # Make
    exif[272] = "Prototype-X1"                    # Model
    exif[315] = "LA2 Sample User"                 # Artist
    exif[36867] = "2026:10:15 10:30:00"           # DateTimeOriginal
    exif[305] = "LA2 Synthetic Metadata Generator"  # Software
    exif[270] = "Synthetic sample for cybersecurity demonstration"  # ImageDescription
    # Deliberately synthetic coordinates, included only to show GPS metadata detection.
    exif[34853] = {1: "N", 2: dms(12.3456), 3: "E", 4: dms(77.1234)}
    image.save(OUTPUT, "JPEG", quality=92, exif=exif)
    print(f"Created: {OUTPUT}")
    print("The image contains synthetic test metadata, not anyone's real location or device data.")


if __name__ == "__main__":
    main()

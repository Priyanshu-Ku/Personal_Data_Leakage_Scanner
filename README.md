# Personal Data Leakage Scanner

A lightweight Cyber Security LA-2 project that uses ExifTool and Python to identify potentially privacy-sensitive metadata in image files, create sanitized copies, and verify the results.

## Components

- `scanner.py` — command-line scanner, risk classification, sanitization, JSON output, and before/after comparison.
- `app.py` — Streamlit dashboard for uploading images, scanning, viewing findings, downloading reports, and optionally sanitizing an image.
- `tools/exiftool.exe` and `tools/exiftool_files/` — ExifTool for Windows (download separately from the official ExifTool website).
- `reports/` — automatically created folder containing saved JSON reports. Reports may contain sensitive metadata such as GPS coordinates; keep this folder private.
- `output/` — used by the command-line cleaner for sanitized copies.

## Requirements

- Windows 10/11
- Python 3.10 or newer
- ExifTool for Windows
- Streamlit (installed from `requirements.txt`)

## 1. Install ExifTool

1. Download the Windows executable package from https://exiftool.org/.
2. Extract it.
3. Rename `exiftool(-k).exe` to `exiftool.exe`.
4. Copy `exiftool.exe` and the complete `exiftool_files` folder into this project's `tools/` folder.

The expected layout is:

```text
Personal_Data_Leakage_Scanner/
├── app.py
├── scanner.py
├── requirements.txt
├── run_dashboard.bat
├── tools/
│   ├── exiftool.exe
│   └── exiftool_files/
├── samples/
├── output/
└── reports/
```

## 2. Install Python dependency

Open PowerShell in the project directory and run:

```powershell
py -m pip install -r requirements.txt
```

## 3. Launch the Streamlit dashboard

```powershell
py -m streamlit run app.py
```

Or double-click `run_dashboard.bat`.

Streamlit will show a local address in the terminal, usually `http://localhost:8501`. Open it in a browser.

The dashboard accepts image formats that ExifTool recognizes as `image/*`. It validates the detected MIME type rather than trusting only the filename extension. The configured upload limit is 20 MB.

## 4. Dashboard workflow

1. Upload an image.
2. Select **Scan image**.
3. Review the overall privacy risk and metadata findings.
4. Download the JSON report. A copy is also saved automatically in `reports/`.
5. Optionally select **Create sanitized copy**.
6. Download the cleaned image and review its verification result. A separate verification report is also saved in `reports/`.

Uploaded originals are held in a temporary directory while scanning and are not permanently saved by the dashboard. Scan reports can contain sensitive metadata values, so protect the `reports/` folder. The app is intended for a local classroom demonstration; do not expose it to the public internet without adding authentication, access controls, and secure storage.

## 5. Command-line usage

```powershell
py scanner.py scan .\samples\demo_photo_with_metadata.jpg --report .\reports\before.json
py scanner.py clean .\samples\demo_photo_with_metadata.jpg --tool exiftool
py scanner.py compare .\samples\demo_photo_with_metadata.jpg .\output\demo_photo_with_metadata_sanitized.jpg
```

## Scope and limitations

- The scanner flags a configured set of metadata tags; it is not a complete privacy or malware scanner.
- ExifTool `Composite` fields are calculated summaries and can duplicate underlying stored tags.
- Filesystem timestamps are reported separately and are not included in the embedded privacy-risk score.
- A `NONE` result means no configured embedded or derived privacy-sensitive tags were detected. It does not prove that every possible metadata element is absent.
- Sanitization should always be followed by a fresh verification scan. Keep the original file until the cleaned copy has been checked.
- The Streamlit dashboard currently handles one uploaded image per scan. Reports are stored locally as JSON files, not in a database.

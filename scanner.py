"""Personal Data Leakage Scanner - a small ExifTool/MAT2 wrapper for LA-2."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
RISK_RULES = [
    ("HIGH", ("gpslatitude", "gpslongitude", "gpsposition", "gpsaltitude", "location", "sublocation"),
     "May reveal where a photo or document was created."),
    ("MEDIUM", ("serialnumber", "cameraserial", "ownername", "artist", "author", "creator", "email", "username"),
     "May identify a person, account, or specific device."),
    ("LOW", ("datetimeoriginal", "createdate", "modifydate", "metadatadate", "software", "creatortool", "make", "model", "copyright"),
     "May reveal timing, software, device type, or attribution details."),
]
SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def find_tool(name: str) -> str | None:
    """Find a tool in PATH or in the project's tools folder."""
    configured = os.environ.get(f"{name.upper()}_PATH")
    candidates = [Path(configured)] if configured else []
    if name == "exiftool":
        candidates += [BASE_DIR / "tools" / "exiftool.exe", BASE_DIR / "tools" / "exiftool"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", check=False)
    except OSError as exc:
        raise RuntimeError(f"Could not start {command[0]}: {exc}") from exc


def read_metadata(file_path: Path) -> dict[str, Any]:
    exiftool = find_tool("exiftool")
    if not exiftool:
        raise RuntimeError("ExifTool not found. Put exiftool.exe and its exiftool_files folder in tools/, "
                           "or add ExifTool to PATH. See tools/README.txt.")
    result = run_command([exiftool, "-json", "-a", "-G1", "-s", str(file_path)])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ExifTool could not read this file.")
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ExifTool returned output that could not be parsed as JSON.") from exc
    return records[0] if records else {}


def metadata_origin(tag: str) -> str:
    """Classify ExifTool groups so file-system data is not confused with embedded tags."""
    group = tag.split(":", 1)[0].casefold()
    return {"system": "filesystem", "composite": "derived", "file": "technical",
            "exiftool": "tool"}.get(group, "embedded")


def classify_tag(tag: str) -> tuple[str, str] | None:
    name = tag.split(":")[-1].replace("_", "").replace("-", "").lower()
    for level, patterns, reason in RISK_RULES:
        if any(pattern in name for pattern in patterns):
            return level, reason
    return None


def analyze(file_path: Path) -> dict[str, Any]:
    metadata = read_metadata(file_path)
    counts = {name: 0 for name in ("embedded", "derived", "filesystem", "technical", "tool")}
    findings = []
    keys = [k for k in metadata if k != "SourceFile" and not k.endswith(":ExifToolVersion")]
    for tag, value in metadata.items():
        if tag == "SourceFile" or tag.endswith(":ExifToolVersion"):
            continue
        origin = metadata_origin(tag)
        counts[origin] += 1
        match = classify_tag(tag)
        if match:
            level, reason = match
            findings.append({"tag": tag, "value": value, "risk": level,
                             "reason": reason, "origin": origin})

    privacy = [f for f in findings if f["origin"] in ("embedded", "derived")]
    overall = max((f["risk"] for f in privacy), key=lambda x: SEVERITY_ORDER[x], default="NONE")
    return {"file": str(file_path), "metadata_fields_read": len(keys), "field_counts": counts,
            "flagged_fields": len(privacy), "overall_risk": overall, "findings": findings}


def print_report(report: dict[str, Any]) -> None:
    counts = report.get("field_counts", {})
    print("\nPERSONAL DATA LEAKAGE SCAN")
    print("=" * 62)
    print(f"File                       : {report['file']}")
    print(f"Metadata fields read       : {report['metadata_fields_read']}")
    print(f"  Embedded metadata fields : {counts.get('embedded', 0)}")
    print(f"  ExifTool-derived fields  : {counts.get('derived', 0)}")
    print(f"  Filesystem fields        : {counts.get('filesystem', 0)}")
    print(f"  Technical/file properties: {counts.get('technical', 0)}")
    print("-" * 62)
    embedded = [f for f in report["findings"] if f.get("origin", metadata_origin(f["tag"])) == "embedded"]
    derived = [f for f in report["findings"] if f.get("origin", metadata_origin(f["tag"])) == "derived"]
    filesystem = [f for f in report["findings"] if f.get("origin", metadata_origin(f["tag"])) == "filesystem"]
    print(f"Sensitive embedded tags   : {len(embedded)}")
    print(f"Derived privacy indicators: {len(derived)}")
    print(f"Filesystem timestamp flags: {len(filesystem)} (informational)")
    print(f"Overall privacy risk      : {report['overall_risk']}")
    print("-" * 62)
    if embedded:
        print("EMBEDDED PRIVACY-SENSITIVE METADATA")
        for item in embedded:
            print(f"[{item['risk']}] {item['tag']}: {item['value']}\n      {item['reason']}")
    else:
        print("No configured privacy-sensitive embedded metadata tags were found.")
    if derived:
        print("\nEXIFTOOL-DERIVED INDICATORS (calculated from other tags)")
        for item in derived:
            print(f"[{item['risk']}] {item['tag']}: {item['value']}\n      Derived summary; not an additional stored metadata field.")
    if filesystem:
        print("\nFILESYSTEM INFORMATION (not included in embedded privacy risk)")
        for item in filesystem:
            print(f"[INFO] {item['tag']}: {item['value']}\n      File-system information reported by the operating system.")
    if not embedded and not derived:
        print("Note: configured tags not detected does not prove all metadata is absent.")


def save_json(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"JSON report saved to: {output_path}")


def clean_file(source: Path, destination: Path, tool: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError(f"Output already exists; choose another name or remove it first: {destination}")
    if tool == "exiftool":
        executable = find_tool("exiftool")
        if not executable:
            raise RuntimeError("ExifTool was not found. See tools/README.txt.")
        result = run_command([executable, "-all=", "-o", str(destination), str(source)])
        if result.returncode != 0 or not destination.exists():
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "ExifTool did not create the cleaned file.")
    else:
        executable = find_tool("mat2")
        if not executable:
            raise RuntimeError("MAT2 was not found. Install it in Linux/WSL and ensure 'mat2' is on PATH.")
        result = run_command([executable, str(source)])
        generated = source.with_name(f"{source.stem}.cleaned{source.suffix}")
        if result.returncode != 0 or not generated.exists():
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "MAT2 did not create the cleaned file.")
        shutil.move(str(generated), str(destination))
    print(f"Cleaned copy created: {destination}")
    print("The original file was not intentionally modified. Verify the cleaned copy before sharing it.")
    return destination


def compare_reports(original: dict[str, Any], cleaned: dict[str, Any]) -> None:
    def sensitive_tags(report: dict[str, Any]) -> set[str]:
        return {f["tag"] for f in report.get("findings", [])
                if f.get("origin", metadata_origin(f["tag"])) in ("embedded", "derived")}

    before, after = sensitive_tags(original), sensitive_tags(cleaned)
    filesystem = sorted(f["tag"] for f in cleaned.get("findings", [])
                        if f.get("origin", metadata_origin(f["tag"])) == "filesystem")
    removed, remaining = sorted(before - after), sorted(after)
    print("\nBEFORE / AFTER COMPARISON")
    print("=" * 62)
    print(f"Privacy-sensitive tags before cleaning: {len(before)}")
    print(f"Privacy-sensitive tags after cleaning : {len(after)}")
    print(f"Sensitive tags no longer detected     : {len(removed)}")
    if removed:
        print("Removed from embedded/derived scan results:")
        for tag in removed:
            print(f"  - {tag}")
    if remaining:
        print("Still detected; review manually:")
        for tag in remaining:
            print(f"  - {tag}")
    else:
        print("No configured privacy-sensitive embedded/derived tags were detected in the cleaned copy.")
    if filesystem:
        print("Filesystem information still reported (informational):")
        for tag in filesystem:
            print(f"  - {tag}")
    print("Note: Composite tags are ExifTool-derived summaries and may duplicate underlying metadata.")
    print("This checks configured tags only; it is not proof that every metadata element is absent.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files for potentially privacy-sensitive metadata.")
    commands = parser.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("scan", help="Read metadata and flag privacy-sensitive fields.")
    scan.add_argument("file", type=Path)
    scan.add_argument("--report", type=Path, help="Optional JSON report output path")
    clean = commands.add_parser("clean", help="Create a sanitized copy of a file.")
    clean.add_argument("file", type=Path)
    clean.add_argument("--tool", choices=("exiftool", "mat2"), default="exiftool")
    clean.add_argument("--output", type=Path, help="Output file path")
    compare = commands.add_parser("compare", help="Compare privacy-sensitive tags before and after cleaning.")
    compare.add_argument("original", type=Path)
    compare.add_argument("cleaned", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "scan":
            source = args.file.expanduser().resolve()
            if not source.is_file():
                raise RuntimeError(f"File does not exist: {source}")
            report = analyze(source)
            print_report(report)
            if args.report:
                save_json(report, args.report.expanduser().resolve())
        elif args.action == "clean":
            source = args.file.expanduser().resolve()
            if not source.is_file():
                raise RuntimeError(f"File does not exist: {source}")
            name = f"{source.stem}_sanitized{source.suffix}"
            destination = args.output.expanduser().resolve() if args.output else BASE_DIR / "output" / name
            clean_file(source, destination, args.tool)
            print("\nVerification scan:")
            print_report(analyze(destination))
        else:
            original, cleaned = args.original.expanduser().resolve(), args.cleaned.expanduser().resolve()
            if not original.is_file() or not cleaned.is_file():
                raise RuntimeError("Both the original and cleaned files must exist.")
            compare_reports(analyze(original), analyze(cleaned))
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

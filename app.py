"""Streamlit dashboard for the Personal Data Leakage Scanner.

Reports are saved locally in ./reports. Uploaded originals are processed from a
short-lived temporary directory and are not permanently stored by this app.
"""
from __future__ import annotations

import hashlib
import html
import mimetypes
import json
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

import scanner

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
MAX_FILE_BYTES = 20 * 1024 * 1024  # 20 MB per image

st.set_page_config(
    page_title="Personal Data Leakage Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def safe_filename(name: str) -> str:
    """Return a safe basename; never trust a browser-supplied path."""
    basename = Path(name.replace("\\", "/")).name
    basename = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")
    return basename or "uploaded_image"


def validate_image(file_path: Path) -> str:
    """Use ExifTool's detected MIME type to accept image formats it supports."""
    metadata = scanner.read_metadata(file_path)
    mime_value = next(
        (value for tag, value in metadata.items()
         if tag.split(":")[-1].casefold() == "mimetype"),
        "",
    )
    file_type = next(
        (value for tag, value in metadata.items()
         if tag.split(":")[-1].casefold() == "filetype"),
        "",
    )

    if not str(mime_value).casefold().startswith("image/"):
        raise ValueError(
            "The uploaded file was not identified by ExifTool as an image. "
            "Please upload an image format supported by ExifTool."
        )
    return str(file_type or mime_value)


def create_scan_report(data: bytes, filename: str) -> dict[str, Any]:
    """Scan uploaded bytes without keeping the original image on disk."""
    original_name = safe_filename(filename)
    suffix = Path(original_name).suffix.lower()

    with tempfile.TemporaryDirectory(prefix="pdl_scan_") as temp_dir:
        temp_path = Path(temp_dir) / f"uploaded{suffix}"
        temp_path.write_bytes(data)
        image_format = validate_image(temp_path)
        report = scanner.analyze(temp_path)

    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["file"] = original_name
    report["original_filename"] = original_name
    report["image_format"] = image_format
    report["file_size_bytes"] = len(data)
    report["sha256"] = hashlib.sha256(data).hexdigest()
    report["scanned_at_utc"] = scanned_at
    report["report_type"] = "image_scan"
    return report


def persist_report(report: dict[str, Any]) -> Path:
    """Persist a JSON report with a collision-resistant filename."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    slug = Path(report.get("original_filename", "image")).stem[:32]
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", slug) or "image"
    report_id = uuid.uuid4().hex[:8]
    output_path = REPORTS_DIR / f"{timestamp}_{slug}_{report_id}.json"
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def scan_category(report: dict[str, Any], origin: str) -> list[dict[str, Any]]:
    return [
        item for item in report.get("findings", [])
        if item.get("origin") == origin
    ]


def risk_message(level: str) -> None:
    if level == "HIGH":
        st.error("HIGH PRIVACY RISK — location or other highly sensitive metadata was detected.")
    elif level == "MEDIUM":
        st.warning("MEDIUM PRIVACY RISK — metadata may identify a person, account, or device.")
    elif level == "LOW":
        st.info("LOW PRIVACY RISK — metadata may reveal timing, software, device, or attribution details.")
    else:
        st.success("NO CONFIGURED EMBEDDED PRIVACY INDICATORS DETECTED — this is not a guarantee that all metadata is absent.")



def render_html_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    """Render a small HTML table without Streamlit's pandas-backed dataframe API."""
    if not rows:
        st.info("No entries to display.")
        return

    header_cells = "".join(
        f'<th style="text-align:left;padding:9px 12px;border-bottom:1px solid #64748b;">{html.escape(label)}</th>'
        for _, label in columns
    )

    body_rows = []
    for row in rows:
        cells = []
        for key, _ in columns:
            value = html.escape(str(row.get(key, "")))
            cells.append(
                '<td style="padding:8px 12px;border-bottom:1px solid rgba(128,128,128,.25);'
                'vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere;">'
                f'{value}</td>'
            )
        body_rows.append("<tr>" + "".join(cells) + "</tr>")

    table_html = (
        '<div style="width:100%;overflow-x:auto;">'
        '<table style="width:100%;border-collapse:collapse;font-size:0.9rem;">'
        f'<thead><tr>{header_cells}</tr></thead>'
        f'<tbody>{"".join(body_rows)}</tbody>'
        '</table></div>'
    )
    # Values are HTML-escaped above, so uploaded metadata cannot inject markup.
    st.markdown(table_html, unsafe_allow_html=True)

def render_findings(report: dict[str, Any]) -> None:
    embedded = scan_category(report, "embedded")
    derived = scan_category(report, "derived")
    filesystem = scan_category(report, "filesystem")
    technical = scan_category(report, "technical")

    tab1, tab2, tab3, tab4 = st.tabs([
        f"Embedded findings ({len(embedded)})",
        f"Derived indicators ({len(derived)})",
        f"Filesystem ({len(filesystem)})",
        f"Technical ({len(technical)})",
    ])

    with tab1:
        if embedded:
            render_html_table(
                [{"risk": x["risk"], "tag": x["tag"], "value": x["value"], "reason": x["reason"]}
                 for x in embedded],
                [("risk", "Risk"), ("tag", "Metadata tag"), ("value", "Value"), ("reason", "Why flagged")],
            )
        else:
            st.success("No configured privacy-sensitive embedded tags were detected.")

    with tab2:
        if derived:
            st.caption("ExifTool calculates these values from underlying metadata. They may repeat the same information and are not additional stored tags.")
            render_html_table(
                [{"risk": x["risk"], "tag": x["tag"], "value": x["value"]}
                 for x in derived],
                [("risk", "Risk"), ("tag", "Derived indicator"), ("value", "Value")],
            )
        else:
            st.write("No configured derived privacy indicators were detected.")

    with tab3:
        st.caption("Filesystem timestamps describe the file on this machine. They are displayed separately and excluded from the embedded privacy-risk score.")
        if filesystem:
            render_html_table(
                [{"tag": x["tag"], "value": x["value"]} for x in filesystem],
                [("tag", "Metadata tag"), ("value", "Value")],
            )
        else:
            st.write("No configured filesystem timestamp flags were detected.")

    with tab4:
        st.caption("Technical fields describe file format or image properties, such as dimensions and encoding.")
        st.metric("Technical fields read", report.get("field_counts", {}).get("technical", 0))
        st.write("These fields are not counted as privacy-risk findings by the current rules.")


def render_report_history() -> None:
    st.subheader("Saved report history")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    saved_reports = sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not saved_reports:
        st.info("No reports have been saved yet. Scan an image to create the first report.")
        return

    options = {
        f"{path.name} ({datetime.fromtimestamp(path.stat().st_mtime).strftime('%d %b %Y, %I:%M:%S %p')})": path
        for path in saved_reports[:100]
    }
    selected_label = st.selectbox("Select a saved report", list(options.keys()), key="history_select")
    selected_path = options[selected_label]
    try:
        saved = json.loads(selected_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not read saved report: {exc}")
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("File", saved.get("original_filename", "Unknown"))
    col2.metric("Privacy risk", saved.get("overall_risk", "Unknown"))
    col3.metric("Flagged embedded/derived", saved.get("flagged_fields", 0))
    st.download_button(
        "Download selected JSON report",
        data=json.dumps(saved, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name=selected_path.name,
        mime="application/json",
        key="download_history_report",
    )


def main() -> None:
    st.title("🛡️ Personal Data Leakage Scanner")
    st.markdown(
        "Inspect images for hidden privacy-sensitive metadata, review the findings, "
        "save a scan report, and optionally create a sanitized copy."
    )

    with st.sidebar:
        st.header("Scanner information")
        st.write("**Metadata engine:** ExifTool")
        st.write("**Risk analysis:** Python")
        st.write("**Sanitization:** ExifTool")
        st.write("**Supported formats:** Image formats recognized by ExifTool")
        st.write("**Maximum upload:** 20 MB")
        st.divider()
        st.caption("Reports are saved locally in the project's reports/ folder. Uploaded originals are not permanently stored by the dashboard.")

    st.warning(
        "Privacy notice: scan reports may contain sensitive values such as GPS coordinates, "
        "author names, or device details. Keep the reports folder private. Use only files "
        "you are authorized to inspect."
    )

    uploaded = st.file_uploader(
        "Upload an image to scan",
        accept_multiple_files=False,
        help="Upload one image up to 20 MB. ExifTool checks the file's detected MIME type before scanning.",
    )

    if uploaded is not None:
        uploaded_name = safe_filename(uploaded.name)
        uploaded_bytes = uploaded.getvalue()
        upload_fingerprint = hashlib.sha256(uploaded_bytes).hexdigest()

        # Clear results from the previous upload when a different image is selected.
        if st.session_state.get("upload_fingerprint") != upload_fingerprint:
            st.session_state["upload_fingerprint"] = upload_fingerprint
            st.session_state.pop("current_report", None)
            st.session_state.pop("current_report_path", None)
            st.session_state.pop("sanitized_bytes", None)
            st.session_state.pop("sanitized_name", None)
            st.session_state.pop("sanitized_verification", None)

        st.write(f"**Filename:** {uploaded_name}")
        st.write(f"**File size:** {len(uploaded_bytes) / 1024:.1f} KB")
        st.write(f"**SHA-256:** `{upload_fingerprint}`")

        scan_clicked = st.button("🔍 Scan image", type="primary", use_container_width=True)
        if scan_clicked:
            try:
                with st.spinner("Validating image and extracting metadata with ExifTool..."):
                    report = create_scan_report(uploaded_bytes, uploaded_name)
                    report_path = persist_report(report)
                st.session_state["current_report"] = report
                st.session_state["current_report_path"] = str(report_path)
                st.session_state.pop("sanitized_bytes", None)
                st.session_state.pop("sanitized_name", None)
                st.session_state.pop("sanitized_verification", None)
                st.success(f"Scan completed. Report saved to: {report_path.relative_to(BASE_DIR)}")
            except (ValueError, RuntimeError, OSError) as exc:
                st.error(f"Scan failed: {exc}")

        report = st.session_state.get("current_report")
        if report and report.get("sha256") == upload_fingerprint:
            st.divider()
            st.subheader("Scan summary")
            risk_message(report.get("overall_risk", "NONE"))

            counts = report.get("field_counts", {})
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Metadata fields", report.get("metadata_fields_read", 0))
            c2.metric("Embedded findings", len(scan_category(report, "embedded")))
            c3.metric("Derived indicators", len(scan_category(report, "derived")))
            c4.metric("Filesystem fields", counts.get("filesystem", 0))

            render_findings(report)

            saved_path = st.session_state.get("current_report_path")
            download_col, path_col = st.columns([1, 2])
            with download_col:
                st.download_button(
                    "Download scan report (JSON)",
                    data=json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"),
                    file_name=Path(saved_path).name if saved_path else "scan_report.json",
                    mime="application/json",
                    key="download_current_report",
                    use_container_width=True,
                )
            with path_col:
                if saved_path:
                    st.caption(f"Stored locally: `{Path(saved_path).relative_to(BASE_DIR)}`")

            st.divider()
            st.subheader("Optional: sanitize this image")
            st.caption("This creates a separate cleaned copy. The uploaded original is not overwritten.")
            if st.button("🧹 Create sanitized copy", key="sanitize_button"):
                try:
                    with st.spinner("Removing metadata and verifying the cleaned image..."):
                        with tempfile.TemporaryDirectory(prefix="pdl_clean_") as temp_dir:
                            source_path = Path(temp_dir) / uploaded_name
                            cleaned_name = f"{Path(uploaded_name).stem}_sanitized{Path(uploaded_name).suffix}"
                            cleaned_path = Path(temp_dir) / cleaned_name
                            source_path.write_bytes(uploaded_bytes)
                            scanner.clean_file(source_path, cleaned_path, "exiftool")
                            cleaned_bytes = cleaned_path.read_bytes()
                            verification = scanner.analyze(cleaned_path)
                            verification["file"] = cleaned_name
                            verification["original_filename"] = cleaned_name
                            verification["report_type"] = "sanitized_image_verification"
                            verification["scanned_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                            verification["sha256"] = hashlib.sha256(cleaned_bytes).hexdigest()
                            verification["file_size_bytes"] = len(cleaned_bytes)
                            verification["image_format"] = report.get("image_format", "Unknown")
                        verification_path = persist_report(verification)
                    st.session_state["sanitized_bytes"] = cleaned_bytes
                    st.session_state["sanitized_name"] = cleaned_name
                    st.session_state["sanitized_verification"] = verification
                    st.session_state["sanitized_report_path"] = str(verification_path)
                    st.success("Sanitized copy created and verification report saved.")
                except (RuntimeError, OSError) as exc:
                    st.error(f"Sanitization failed: {exc}")

            if st.session_state.get("sanitized_bytes"):
                cleaned_bytes = st.session_state["sanitized_bytes"]
                cleaned_name = st.session_state["sanitized_name"]
                verification = st.session_state["sanitized_verification"]
                st.download_button(
                    "Download sanitized image",
                    data=cleaned_bytes,
                    file_name=cleaned_name,
                    mime=mimetypes.guess_type(cleaned_name)[0] or "application/octet-stream",
                    key="download_sanitized_image",
                )
                st.write(f"**Verification risk:** {verification.get('overall_risk', 'Unknown')}")
                st.write(f"**Remaining configured privacy-sensitive tags:** {verification.get('flagged_fields', 0)}")
                st.caption("The verification JSON is also saved in the reports/ folder.")

    st.divider()
    with st.expander("View saved scan reports", expanded=False):
        render_report_history()

    st.caption(
        "Educational prototype for the Cyber Security LA-2 assessment. "
        "A NONE result means no configured privacy-sensitive tags were detected; "
        "it does not prove that every possible metadata element is absent."
    )


if __name__ == "__main__":
    main()

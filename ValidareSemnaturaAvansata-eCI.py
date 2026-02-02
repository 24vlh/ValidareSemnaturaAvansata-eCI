#!/usr/bin/env python3
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import logging
import subprocess
import sys
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List, Set

from PIL import Image, ImageTk

# GUI (stdlib)
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText
except Exception:
    tk = None
    filedialog = None
    messagebox = None
    ttk = None
    ScrolledText = None

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509 as asn1_x509
from asn1crypto import cms as asn1_cms


# =============================================================================
# Versioning / Identity
# =============================================================================
APP_NAME = "Validare Semnătură Avansată cu eCI"
APP_VERSION = "2.0.3"
APP_AUTHOR = "vlah.io • @24vlh"

APP_CHANGELOG = [
    ("2.0.3", "Rebranding: ValidareSemnatura-eCI → ValidareSemnaturaAvansata-eCI"),
    ("2.0.2", "CLI implementat + output (--output, --no-stdout)"),
    ("2.0.1", "Curățare text/UI + corecții micro (multi + audit)"),
    ("2.0.0", "Multi semnături, verificări criptografice extinse, opțiuni + taburi noi"),
    ("1.0.0", "Validare tehnică: integritate, criptografie, lanț Root/Sub MAI + emitent strict + GUI/CLI"),
]

# =============================================================================
# eCI strict mode config (MAI pins + optional policy/EKU constraints)
# =============================================================================
MAI_ROOT_SHA256 = {
    "b7a766f52218c8083e936f9ab085e97c67671ecd4fd3069b641c638072e44b1d",
}
MAI_SUB_SHA256 = {
    "b512f92a6d156008d93ab5ff9690be874afc3401ce0306f477f187799593da80",
}

# Optional: set these to enforce EKU/policy OIDs in strict eCI mode
ECI_REQUIRED_EKU_OIDS: Set[str] = set()
ECI_REQUIRED_POLICY_OIDS: Set[str] = {"1.3.6.1.4.1.62458.1.1.2"}


# =============================================================================
# Paths / UX helpers
# =============================================================================
def resource_path(rel: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / rel  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent / rel


def _load_build_date() -> str:
    candidates = [
        resource_path("assets/build_info.json"),
        resource_path("build_info.json"),
    ]
    for path in candidates:
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    val = data.get("build_date")
                    if isinstance(val, str) and val.strip():
                        return val.strip()
        except Exception:
            pass
    try:
        if getattr(sys, "frozen", False):
            return datetime.fromtimestamp(Path(sys.executable).stat().st_mtime).strftime("%Y-%m-%d")
        return datetime.fromtimestamp(Path(__file__).stat().st_mtime).strftime("%Y-%m-%d")
    except Exception:
        return "UNKNOWN"


APP_BUILD = _load_build_date()


def open_url(url: str) -> bool:
    try:
        if webbrowser.open(url, new=2):
            return True
    except Exception:
        pass
    try:
        os.startfile(url)  # type: ignore[attr-defined]
        return True
    except Exception:
        pass
    try:
        subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)
        return True
    except Exception:
        return False


def now_stamp_local() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# =============================================================================
# CLI helpers
# =============================================================================
def bundled_cert_paths() -> Tuple[Path, Path]:
    return (
        resource_path("assets/certs/ro_cei_mai_root-ca.cer"),
        resource_path("assets/certs/ro_cei_mai_sub-ca.cer"),
    )


def load_local_crls_from_assets() -> List[bytes]:
    crls: List[bytes] = []
    crl_dir = resource_path("assets/certs")
    if crl_dir.exists():
        for p in sorted(crl_dir.rglob("*.crl")):
            try:
                crls.append(p.read_bytes())
            except Exception:
                continue
    return crls


def _normalize_cli_options(
    allow_fetching: bool,
    revocation_mode: str,
    strict_issuer: bool,
    strict_eci: bool,
    local_crls: Optional[List[bytes]],
) -> Tuple[bool, str, bool]:
    if strict_eci:
        allow_fetching = True
        revocation_mode = "require"
        strict_issuer = True
    if not allow_fetching and not local_crls:
        revocation_mode = "soft-fail"
    return allow_fetching, revocation_mode, strict_issuer


def run_cli(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="ValidareSemnaturaAvansata-eCI",
        description="Validate PDF signatures against MAI Root/Sub CA (CLI mode).",
    )
    parser.add_argument("--cli", action="store_true", help="Force CLI mode.")
    parser.add_argument("--pdf", required=True, help="Path to signed PDF.")
    parser.add_argument("--root", help="Path to Root CA (.cer/.crt/.pem).")
    parser.add_argument("--sub", help="Path to Sub CA (.cer/.crt/.pem).")
    parser.add_argument(
        "--use-bundled",
        action="store_true",
        help="Use bundled MAI Root/Sub from assets/certs.",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable text.")
    parser.add_argument(
        "--output",
        help="Write output to a file (JSON if --json is set, otherwise human-readable text).",
    )
    parser.add_argument(
        "--no-stdout",
        action="store_true",
        help="Do not print output to stdout (useful with --output).",
    )
    parser.add_argument(
        "--allow-fetching",
        action="store_true",
        help="Allow network fetching for CRL/AIA/OCSP.",
    )
    parser.add_argument(
        "--revocation-mode",
        default="soft-fail",
        choices=["soft-fail", "hard-fail", "require"],
        help="Revocation mode (effective when fetching is enabled).",
    )
    parser.add_argument("--strict-issuer", action="store_true", help="Require signer to be issued by provided Sub CA.")
    parser.add_argument("--hard-mode", action="store_true", help="Reject extra embedded certs in CMS.")
    parser.add_argument("--strict-eci", action="store_true", help="Enable strict eCI mode (MAI pin + policies).")
    parser.add_argument("--local-crl", action="store_true", help="Use local CRLs from assets/certs/*.crl.")
    parser.add_argument("--timestamp", action="store_true", help="Require valid trusted timestamp (if present).")

    args = parser.parse_args(argv)

    if args.no_stdout and not args.output:
        parser.error("--no-stdout requires --output.")

    if args.use_bundled:
        root_path, sub_path = bundled_cert_paths()
    else:
        if not args.root or not args.sub:
            parser.error("You must provide --root and --sub, or use --use-bundled.")
        root_path = Path(args.root).expanduser()
        sub_path = Path(args.sub).expanduser()

    if not root_path.exists():
        print(f"NO_SUCH_ROOT_CA: {root_path}", file=sys.stderr)
        return 2
    if not sub_path.exists():
        print(f"NO_SUCH_SUB_CA: {sub_path}", file=sys.stderr)
        return 2

    pdf_path = Path(args.pdf).expanduser()
    if not pdf_path.exists():
        print(f"NO_SUCH_PDF: {pdf_path}", file=sys.stderr)
        return 2

    local_crls = load_local_crls_from_assets() if args.local_crl else None
    allow_fetching, revocation_mode, strict_issuer = _normalize_cli_options(
        allow_fetching=bool(args.allow_fetching),
        revocation_mode=str(args.revocation_mode),
        strict_issuer=bool(args.strict_issuer),
        strict_eci=bool(args.strict_eci),
        local_crls=local_crls,
    )

    strict_eci = bool(args.strict_eci)
    hard_mode = bool(args.hard_mode)
    require_timestamp = bool(args.timestamp)

    try:
        with pdf_path.open("rb") as f:
            r = PdfFileReader(f)
            sigs = r.embedded_signatures or []
            sig_count = len(sigs)
    except Exception as e:
        print(f"EXCEPTION: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    if sig_count > 1:
        root_cert = _load_cert_any(root_path)
        sub_cert = _load_cert_any(sub_path)
        root_fp = _cert_sha256_der(root_cert)
        sub_fp = _cert_sha256_der(sub_cert)

        results: List[Result] = []
        if strict_eci and root_fp not in MAI_ROOT_SHA256:
            base = Result(
                ok=False,
                message="STRICT_ECI_ROOT_NOT_MAI",
                signature_count=sig_count,
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=strict_issuer,
                hard_mode_enabled=hard_mode,
                allow_fetching_enabled=allow_fetching,
                revocation_mode=revocation_mode,
                local_crl_enabled=bool(local_crls),
                local_crl_count=len(local_crls or []),
                timestamp_check_enabled=bool(require_timestamp),
                timestamp_ok=None,
                timestamp_info=None,
                strict_eci_enabled=True,
                strict_eci_ok=False,
                strict_eci_notes=["Root CA nu corespunde amprentei MAI."],
                used_root_path=str(root_path),
                used_sub_path=str(sub_path),
            )
            results = [Result(**base.__dict__) for _ in sigs]
        elif strict_eci and sub_fp not in MAI_SUB_SHA256:
            base = Result(
                ok=False,
                message="STRICT_ECI_SUB_NOT_MAI",
                signature_count=sig_count,
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=strict_issuer,
                hard_mode_enabled=hard_mode,
                allow_fetching_enabled=allow_fetching,
                revocation_mode=revocation_mode,
                local_crl_enabled=bool(local_crls),
                local_crl_count=len(local_crls or []),
                timestamp_check_enabled=bool(require_timestamp),
                timestamp_ok=None,
                timestamp_info=None,
                strict_eci_enabled=True,
                strict_eci_ok=False,
                strict_eci_notes=["Sub CA nu corespunde amprentei MAI."],
                used_root_path=str(root_path),
                used_sub_path=str(sub_path),
            )
            results = [Result(**base.__dict__) for _ in sigs]
        else:
            for embedded_sig in sigs:
                res = validate_embedded_signature_against_two_cas(
                    embedded_sig=embedded_sig,
                    signature_count=sig_count,
                    root_cert=root_cert,
                    sub_cert=sub_cert,
                    root_fp=root_fp,
                    sub_fp=sub_fp,
                    allow_fetching=allow_fetching,
                    revocation_mode=revocation_mode,
                    strict_issuer=strict_issuer,
                    hard_mode=hard_mode,
                    strict_eci=strict_eci,
                    local_crls=local_crls,
                    require_timestamp=require_timestamp,
                    root_ca_path=root_path,
                    sub_ca_path=sub_path,
                )
                results.append(res)

        if args.json:
            output_text = json.dumps([r.__dict__ for r in results], ensure_ascii=False, indent=2)
        else:
            parts: List[str] = []
            for idx, res in enumerate(results, start=1):
                parts.append(f"=== Semnătura {idx} ===")
                parts.append(result_to_human(res))
                parts.append("")
            output_text = "\n".join(parts).rstrip() + "\n"

        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")

        if not args.no_stdout:
            print(output_text, end="")

        return 0 if results and all(r.ok for r in results) else 1

    res = validate_pdf_against_two_cas(
        pdf_path=pdf_path,
        root_ca_path=root_path,
        sub_ca_path=sub_path,
        allow_fetching=allow_fetching,
        revocation_mode=revocation_mode,
        strict_issuer=strict_issuer,
        hard_mode=hard_mode,
        strict_eci=strict_eci,
        local_crls=local_crls,
        require_timestamp=require_timestamp,
    )

    output_text = result_to_json(res) if args.json else result_to_human(res)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")

    if not args.no_stdout:
        print(output_text)

    return 0 if res.ok else 1

# =============================================================================
# Result model
# =============================================================================
@dataclass
class Result:
    ok: bool
    message: str

    signature_intact: bool = False
    signature_valid: bool = False
    signature_trusted: bool = False

    coverage_entire_file: bool = False
    modification_none: bool = False
    signature_count: int = 0

    signer_subject: Optional[str] = None
    signer_issuer: Optional[str] = None
    signer_cert_sha256: Optional[str] = None
    signer_eku_oids: Optional[List[str]] = None
    signer_policy_oids: Optional[List[str]] = None
    signer_key_usage: Optional[str] = None
    signer_not_before: Optional[str] = None
    signer_not_after: Optional[str] = None

    root_cert_sha256: Optional[str] = None
    sub_cert_sha256: Optional[str] = None

    strict_issuer_enabled: bool = False
    strict_issuer_expected: Optional[str] = None
    strict_issuer_actual: Optional[str] = None
    strict_issuer_verified_by_signature: Optional[bool] = None
    strict_issuer_name_match: Optional[bool] = None

    hard_mode_enabled: bool = False
    hard_mode_ok: Optional[bool] = None
    hard_mode_extra_certs: Optional[List[str]] = None

    allow_fetching_enabled: bool = False
    revocation_mode: Optional[str] = None
    local_crl_enabled: bool = False
    local_crl_count: int = 0
    timestamp_check_enabled: bool = False
    timestamp_ok: Optional[bool] = None
    timestamp_info: Optional[str] = None
    timestamp_value: Optional[str] = None
    timestamp_tsa_subject: Optional[str] = None
    content_timestamp_value: Optional[str] = None
    content_timestamp_tsa_subject: Optional[str] = None

    strict_eci_enabled: bool = False
    strict_eci_ok: Optional[bool] = None
    strict_eci_notes: Optional[List[str]] = None

    # version identity baked into every output
    app_name: str = APP_NAME
    app_version: str = APP_VERSION
    app_build: str = APP_BUILD

    # informational: which cert paths were used (for reproducibility)
    used_root_path: Optional[str] = None
    used_sub_path: Optional[str] = None

    details: Optional[Dict[str, Any]] = None


def result_to_json(res: Result) -> str:
    return json.dumps(res.__dict__, ensure_ascii=False, indent=2)


def result_to_human(res: Result) -> str:
    verdict = "VALID ✅" if res.ok else "INVALID ❌"

    def yn(v: Optional[bool]) -> str:
        if v is True:
            return "DA"
        if v is False:
            return "NU"
        return "UNKNOWN"

    lines: List[str] = []
    lines.append(verdict)
    lines.append(f"Motiv: {res.message}")
    lines.append("")

    lines.append("Controale (tehnic):")
    lines.append(f"• Integritate (intact): {yn(res.signature_intact)}")
    lines.append(f"• Semnătură criptografică (valid): {yn(res.signature_valid)}")
    lines.append(f"• Lanț de încredere Root/Sub (trusted): {yn(res.signature_trusted)}")
    lines.append("")

    lines.append("Controale (politică):")
    lines.append(f"• Acoperire ENTIRE FILE: {yn(res.coverage_entire_file)}")
    lines.append(f"• Fără modificări după semnare: {yn(res.modification_none)}")
    lines.append(f"• Număr semnături în PDF: {res.signature_count}")
    lines.append("")

    lines.append("Opțiuni:")
    lines.append(f"• Revocare/lanț via rețea (CRL/AIA): {yn(res.allow_fetching_enabled)}")
    if res.revocation_mode:
        lines.append(f"  – Mod revocare: {res.revocation_mode}")
    lines.append(f"• CRL local (assets/certs/*.crl): {yn(res.local_crl_enabled)}")
    if res.local_crl_enabled:
        lines.append(f"  – CRL încărcate: {res.local_crl_count}")
    lines.append(f"• Verificare timestamp/LTV: {yn(res.timestamp_check_enabled)}")
    if res.timestamp_check_enabled:
        lines.append(f"  – Timestamp OK: {yn(res.timestamp_ok)}")
        if res.timestamp_info:
            lines.append(f"  – {res.timestamp_info}")
    if res.timestamp_value:
        lines.append(f"  – Timestamp: {res.timestamp_value}")
    if res.timestamp_tsa_subject:
        lines.append(f"  – TSA: {res.timestamp_tsa_subject}")
    if res.content_timestamp_value:
        lines.append(f"  – Content TS: {res.content_timestamp_value}")
    if res.content_timestamp_tsa_subject:
        lines.append(f"  – Content TSA: {res.content_timestamp_tsa_subject}")
    if res.timestamp_check_enabled and res.timestamp_ok is False:
        lines.append("  – Atenție: timestamp prezent dar invalid sau netrusted.")
    lines.append(f"• Emitent strict (pin Sub CA): {yn(res.strict_issuer_enabled)}")
    if res.strict_issuer_enabled:
        lines.append(f"  – Nume emitent corect: {yn(res.strict_issuer_name_match)}")
        lines.append(f"  – Semnătura emitentului verificată: {yn(res.strict_issuer_verified_by_signature)}")
    lines.append(f"• Hard mode (respinge certificate embedded suplimentare): {yn(res.hard_mode_enabled)}")
    if res.hard_mode_enabled:
        lines.append(f"  – Hard mode OK: {yn(res.hard_mode_ok)}")
        if res.hard_mode_extra_certs:
            lines.append("  – Certificate extra (SHA256):")
            for fp in res.hard_mode_extra_certs:
                lines.append(f"    * {fp}")
    lines.append(f"• Strict eCI (MAI pin + politici): {yn(res.strict_eci_enabled)}")
    if res.strict_eci_enabled:
        lines.append(f"  – Strict eCI OK: {yn(res.strict_eci_ok)}")
        if res.strict_eci_notes:
            for n in res.strict_eci_notes:
                lines.append(f"  – {n}")
    lines.append("")

    lines.append("Identitate certificat semnatar (informativ):")
    lines.append(f"• Subject: {res.signer_subject or 'UNKNOWN'}")
    lines.append(f"• Emitent: {res.signer_issuer or 'UNKNOWN'}")
    lines.append(f"• Signer SHA256: {res.signer_cert_sha256 or 'UNKNOWN'}")
    if res.signer_not_before:
        lines.append(f"• Not Before: {res.signer_not_before}")
    if res.signer_not_after:
        lines.append(f"• Not After: {res.signer_not_after}")
    if res.signer_key_usage:
        lines.append(f"• Key Usage: {res.signer_key_usage}")
    if res.signer_eku_oids:
        lines.append(f"• EKU OIDs: {', '.join(res.signer_eku_oids)}")
    if res.signer_policy_oids:
        lines.append(f"• Policy OIDs: {', '.join(res.signer_policy_oids)}")
    lines.append("")

    lines.append("CA-urile folosite (pinned):")
    lines.append(f"• Root SHA256: {res.root_cert_sha256 or 'UNKNOWN'}")
    lines.append(f"• Sub  SHA256: {res.sub_cert_sha256 or 'UNKNOWN'}")
    lines.append(f"• Root path: {res.used_root_path or 'UNKNOWN'}")
    lines.append(f"• Sub  path: {res.used_sub_path or 'UNKNOWN'}")
    lines.append("")

    lines.append(f"{res.app_name} v{res.app_version} (build {res.app_build})")
    return "\n".join(lines)


# =============================================================================
# Cert helpers
# =============================================================================
def _load_cert_any(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


def _cert_sha256_der(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _to_asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    der = cert.public_bytes(serialization.Encoding.DER)
    return asn1_x509.Certificate.load(der)


# =============================================================================
# Policy helpers (robust across enum/string representations)
# =============================================================================
def _is_entire_file_coverage(val: Any) -> bool:
    s = str(val) if val is not None else ""
    return ("ENTIRE_FILE" in s) or s.endswith(".ENTIRE_FILE")


def _is_modification_none(val: Any) -> bool:
    s = str(val) if val is not None else ""
    return ("NONE" in s) or s.endswith(".NONE")
# =============================================================================
# Strict issuer (cryptographic pin)
# =============================================================================
def _verify_cert_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    pub = issuer.public_key()
    sig = child.signature
    tbs = child.tbs_certificate_bytes
    h = child.signature_hash_algorithm  # None for Ed25519/Ed448

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if h is None:
                return False
            pub.verify(sig, tbs, padding.PKCS1v15(), h)
            return True

        if isinstance(pub, ec.EllipticCurvePublicKey):
            if h is None:
                return False
            pub.verify(sig, tbs, ec.ECDSA(h))
            return True

        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, tbs)
            return True

        if isinstance(pub, ed448.Ed448PublicKey):
            pub.verify(sig, tbs)
            return True

        return False
    except Exception:
        return False


# =============================================================================
# eCI strict checks (EKU / policy)
# =============================================================================
def _extract_eku_oids(cert: x509.Certificate) -> List[str]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return [oid.dotted_string for oid in eku]
    except Exception:
        return []


def _extract_policy_oids(cert: x509.Certificate) -> List[str]:
    try:
        pol = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
        return [p.policy_identifier.dotted_string for p in pol]
    except Exception:
        return []


def _find_signer_cert_from_signed_data(
    signed_data: asn1_cms.SignedData, signer_info: asn1_cms.SignerInfo
) -> Optional[asn1_x509.Certificate]:
    certs = signed_data.get("certificates", None)
    if certs is None:
        return None

    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        iss = sid.chosen["issuer"]
        serial = sid.chosen["serial_number"].native
        for cert_choice in certs:
            try:
                if cert_choice.name != "certificate":
                    continue
                cert = cert_choice.chosen
                if cert.serial_number.native == serial and cert.issuer == iss:
                    return cert
            except Exception:
                continue
    elif sid.name == "subject_key_identifier":
        ski = sid.chosen.native
        for cert_choice in certs:
            try:
                if cert_choice.name != "certificate":
                    continue
                cert = cert_choice.chosen
                for ext in cert["tbs_certificate"]["extensions"]:
                    if ext["extn_id"].dotted == "2.5.29.14":
                        if ext["extn_value"].native == ski:
                            return cert
            except Exception:
                continue
    return None


def _save_signer_cert_bytes(pdf_path: Path, dest: Path) -> bool:
    """
    Extract signer cert from PDF and save as DER .cer.
    No validation; best-effort.
    """
    try:
        with pdf_path.open("rb") as f:
            r = PdfFileReader(f)
            sigs = r.embedded_signatures or []
            if not sigs:
                return False
            embedded_sig = sigs[0]
            signer = _find_signer_cert_from_signed_data(
                embedded_sig.signed_data, embedded_sig.signer_info
            )
            if signer is None:
                return False
            dest.write_bytes(signer.dump())
            return True
    except Exception:
        return False


def _save_signer_cert_bytes_from_embedded(embedded_sig: Any, dest: Path) -> bool:
    """
    Extract signer cert from an embedded signature and save as DER .cer.
    No validation; best-effort.
    """
    try:
        signer = _find_signer_cert_from_signed_data(
            embedded_sig.signed_data, embedded_sig.signer_info
        )
        if signer is None:
            return False
        dest.write_bytes(signer.dump())
        return True
    except Exception:
        return False


# =============================================================================
# Hard mode: reject extra embedded certs in CMS
# =============================================================================
def _extract_cms_signature_bytes(embedded_sig: Any) -> bytes:
    """
    Best-effort extraction of CMS/PKCS#7 bytes from /Contents.
    Fail closed if we cannot parse.
    """
    candidates: List[Any] = []
    for attr in ("sig_object", "sig_obj", "sig_dict", "signature_object"):
        if hasattr(embedded_sig, attr):
            candidates.append(getattr(embedded_sig, attr))
    for attr in ("sig_field", "field", "field_dict"):
        if hasattr(embedded_sig, attr):
            candidates.append(getattr(embedded_sig, attr))

    contents_obj = None
    for cand in candidates:
        try:
            if cand is None:
                continue
            if isinstance(cand, dict) and "/Contents" in cand:
                contents_obj = cand["/Contents"]
                break
            if hasattr(cand, "__contains__") and "/Contents" in cand:
                contents_obj = cand["/Contents"]
                break
        except Exception:
            continue

    if contents_obj is None:
        raise ValueError("Cannot locate /Contents in signature dictionary.")

    if isinstance(contents_obj, bytes):
        raw = contents_obj
    elif isinstance(contents_obj, str):
        raw = binascii.unhexlify(contents_obj.strip())
    else:
        if hasattr(contents_obj, "native"):
            nat = contents_obj.native
            if isinstance(nat, bytes):
                raw = nat
            elif isinstance(nat, str):
                raw = binascii.unhexlify(nat.strip())
            else:
                raise ValueError("Unsupported /Contents native type.")
        elif hasattr(contents_obj, "original_bytes"):
            raw = contents_obj.original_bytes
        else:
            raise ValueError("Unsupported /Contents type; cannot extract CMS bytes.")

    return raw.rstrip(b"\x00")


def _cms_embedded_cert_fingerprints_sha256(cms_der: bytes) -> List[str]:
    ci = asn1_cms.ContentInfo.load(cms_der)
    if ci["content_type"].native != "signed_data":
        return []
    sd = ci["content"]
    certs = sd.get("certificates", None)
    if certs is None:
        return []

    fps: List[str] = []
    for cert_choice in certs:
        try:
            if cert_choice.name != "certificate":
                continue
            der = cert_choice.chosen.dump()
            fps.append(hashlib.sha256(der).hexdigest())
        except Exception:
            continue
    return fps


def _hard_mode_check(embedded_sig: Any, allowed_fps: Set[str]) -> Tuple[bool, List[str]]:
    cms_bytes = _extract_cms_signature_bytes(embedded_sig)
    embedded_fps = _cms_embedded_cert_fingerprints_sha256(cms_bytes)
    extras = sorted({fp for fp in embedded_fps if fp not in allowed_fps})
    return (len(extras) == 0), extras


# =============================================================================
# Core validator
# =============================================================================
def validate_pdf_against_two_cas(
    pdf_path: Path,
    root_ca_path: Path,
    sub_ca_path: Path,
    allow_fetching: bool = False,
    revocation_mode: str = "soft-fail",
    strict_issuer: bool = False,
    hard_mode: bool = False,
    strict_eci: bool = False,
    local_crls: Optional[List[bytes]] = None,
    require_timestamp: bool = False,
) -> Result:
    if not pdf_path.exists():
        return Result(ok=False, message=f"NO_SUCH_PDF: {pdf_path}")

    if not root_ca_path.exists():
        return Result(ok=False, message=f"NO_SUCH_ROOT_CA: {root_ca_path}")

    if not sub_ca_path.exists():
        return Result(ok=False, message=f"NO_SUCH_SUB_CA: {sub_ca_path}")

    if strict_eci:
        allow_fetching = True
        revocation_mode = "require"
        strict_issuer = True
    if not allow_fetching and not local_crls:
        revocation_mode = "soft-fail"

    root_cert = _load_cert_any(root_ca_path)
    sub_cert = _load_cert_any(sub_ca_path)

    root_fp = _cert_sha256_der(root_cert)
    sub_fp = _cert_sha256_der(sub_cert)

    strict_eci_enabled = bool(strict_eci)
    strict_eci_notes: List[str] = []

    if strict_eci:
        if root_fp not in MAI_ROOT_SHA256:
            return Result(
                ok=False,
                message="STRICT_ECI_ROOT_NOT_MAI",
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=strict_issuer,
                hard_mode_enabled=hard_mode,
                allow_fetching_enabled=allow_fetching,
                revocation_mode=revocation_mode,
                timestamp_check_enabled=bool(require_timestamp),
                timestamp_ok=None,
                timestamp_info=None,
                strict_eci_enabled=True,
                strict_eci_ok=False,
                strict_eci_notes=["Root CA nu corespunde amprentei MAI."],
                used_root_path=str(root_ca_path),
                used_sub_path=str(sub_ca_path),
            )
        if sub_fp not in MAI_SUB_SHA256:
            return Result(
                ok=False,
                message="STRICT_ECI_SUB_NOT_MAI",
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=strict_issuer,
                hard_mode_enabled=hard_mode,
                allow_fetching_enabled=allow_fetching,
                revocation_mode=revocation_mode,
                timestamp_check_enabled=bool(require_timestamp),
                timestamp_ok=None,
                timestamp_info=None,
                strict_eci_enabled=True,
                strict_eci_ok=False,
                strict_eci_notes=["Sub CA nu corespunde amprentei MAI."],
                used_root_path=str(root_ca_path),
                used_sub_path=str(sub_ca_path),
            )

    vc = ValidationContext(
        trust_roots=[_to_asn1(root_cert)],
        other_certs=[_to_asn1(sub_cert)],
        allow_fetching=allow_fetching,
        revocation_mode=revocation_mode,
        crls=local_crls,
    )

    try:
        with pdf_path.open("rb") as f:
            r = PdfFileReader(f)
            sigs = r.embedded_signatures or []
            sig_count = len(sigs)

            if sig_count == 0:
                return Result(
                    ok=False,
                    message="NO_SIGNATURES_IN_PDF",
                    signature_count=0,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=hard_mode,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=bool(require_timestamp),
                    timestamp_ok=None,
                    timestamp_info=None,
                    strict_eci_enabled=strict_eci_enabled,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                )

            if sig_count != 1:
                return Result(
                    ok=False,
                    message="PDF_MUST_HAVE_EXACTLY_ONE_SIGNATURE",
                    signature_count=sig_count,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=hard_mode,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=bool(require_timestamp),
                    timestamp_ok=None,
                    timestamp_info=None,
                    strict_eci_enabled=strict_eci_enabled,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                )

            embedded_sig = sigs[0]
            status = validate_pdf_signature(embedded_sig, vc)

            intact = bool(getattr(status, "intact", False))
            valid = bool(getattr(status, "valid", False))
            trusted = bool(getattr(status, "trusted", False))
            ts_validity = getattr(status, "timestamp_validity", None)
            content_ts_validity = getattr(status, "content_timestamp_validity", None)
            timestamp_ok: Optional[bool] = None
            timestamp_info: Optional[str] = None
            ts_value: Optional[str] = None
            ts_tsa_subject: Optional[str] = None
            cts_value: Optional[str] = None
            cts_tsa_subject: Optional[str] = None
            if ts_validity is not None:
                try:
                    ts_value = ts_validity.timestamp.isoformat()
                except Exception:
                    ts_value = None
                try:
                    ts_tsa_subject = ts_validity.signing_cert.subject.human_friendly
                except Exception:
                    ts_tsa_subject = None
            if content_ts_validity is not None:
                try:
                    cts_value = content_ts_validity.timestamp.isoformat()
                except Exception:
                    cts_value = None
                try:
                    cts_tsa_subject = content_ts_validity.signing_cert.subject.human_friendly
                except Exception:
                    cts_tsa_subject = None
            if require_timestamp:
                any_ts = ts_validity or content_ts_validity
                if any_ts is None:
                    timestamp_ok = False
                    timestamp_info = "Nu există timestamp validabil în semnătură."
                else:
                    ok_list = []
                    if ts_validity is not None:
                        ok_list.append(bool(ts_validity.valid and ts_validity.intact and ts_validity.trusted))
                    if content_ts_validity is not None:
                        ok_list.append(
                            bool(content_ts_validity.valid and content_ts_validity.intact and content_ts_validity.trusted)
                        )
                    timestamp_ok = any(ok_list)
                    timestamp_info = "Timestamp valid și de încredere." if timestamp_ok else "Timestamp prezent dar invalid."

            coverage = getattr(status, "coverage", None)
            modification_level = getattr(status, "modification_level", None)

            coverage_entire = _is_entire_file_coverage(coverage)
            modification_none = _is_modification_none(modification_level)

            # Extract signer cert
            signer_asn1 = None
            signer_crypto: Optional[x509.Certificate] = None
            signer_subject = None
            signer_issuer = None
            signer_fp = None
            signer_eku_oids: Optional[List[str]] = None
            signer_policy_oids: Optional[List[str]] = None
            signer_key_usage: Optional[str] = None
            signer_not_before: Optional[str] = None
            signer_not_after: Optional[str] = None

            try:
                signer_asn1 = status.signing_cert
            except Exception:
                signer_asn1 = None

            if signer_asn1 is not None:
                try:
                    signer_subject = signer_asn1.subject.human_friendly
                    signer_issuer = signer_asn1.issuer.human_friendly
                    signer_fp = hashlib.sha256(signer_asn1.dump()).hexdigest()
                    signer_crypto = x509.load_der_x509_certificate(signer_asn1.dump())
                except Exception:
                    signer_crypto = None

            if signer_crypto is not None:
                try:
                    signer_key_usage = str(
                        signer_crypto.extensions.get_extension_for_class(x509.KeyUsage).value
                    )
                except Exception:
                    signer_key_usage = None
                signer_eku_oids = _extract_eku_oids(signer_crypto)
                signer_policy_oids = _extract_policy_oids(signer_crypto)
                try:
                    signer_not_before = signer_crypto.not_valid_before.isoformat()
                    signer_not_after = signer_crypto.not_valid_after.isoformat()
                except Exception:
                    signer_not_before = None
                    signer_not_after = None

            # Strict eCI checks (fail-closed)
            strict_eci_ok: Optional[bool] = None
            if strict_eci_enabled:
                if signer_crypto is None:
                    return Result(
                        ok=False,
                        message="STRICT_ECI_NO_SIGNER_CERT",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        signer_eku_oids=signer_eku_oids,
                        signer_policy_oids=signer_policy_oids,
                        signer_key_usage=signer_key_usage,
                        signer_not_before=signer_not_before,
                        signer_not_after=signer_not_after,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=hard_mode,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        strict_eci_enabled=True,
                        strict_eci_ok=False,
                        strict_eci_notes=["Nu pot extrage certificatul semnatarului."],
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                    )

                # Key usage check
                try:
                    ku = signer_crypto.extensions.get_extension_for_class(x509.KeyUsage).value
                    if not (ku.digital_signature or ku.content_commitment):
                        return Result(
                            ok=False,
                            message="STRICT_ECI_KEY_USAGE_FAIL",
                            signature_intact=intact,
                            signature_valid=valid,
                            signature_trusted=trusted,
                            coverage_entire_file=coverage_entire,
                            modification_none=modification_none,
                            signature_count=1,
                            signer_subject=signer_subject,
                            signer_issuer=signer_issuer,
                            signer_cert_sha256=signer_fp,
                            root_cert_sha256=root_fp,
                            sub_cert_sha256=sub_fp,
                            strict_issuer_enabled=strict_issuer,
                            hard_mode_enabled=hard_mode,
                            allow_fetching_enabled=allow_fetching,
                            revocation_mode=revocation_mode,
                            local_crl_enabled=bool(local_crls),
                            local_crl_count=len(local_crls or []),
                            strict_eci_enabled=True,
                            strict_eci_ok=False,
                            strict_eci_notes=["KeyUsage nu include digitalSignature/contentCommitment."],
                            used_root_path=str(root_ca_path),
                            used_sub_path=str(sub_ca_path),
                        )
                except Exception:
                    return Result(
                        ok=False,
                        message="STRICT_ECI_KEY_USAGE_MISSING",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        signer_eku_oids=signer_eku_oids,
                        signer_policy_oids=signer_policy_oids,
                        signer_key_usage=signer_key_usage,
                        signer_not_before=signer_not_before,
                        signer_not_after=signer_not_after,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=hard_mode,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        strict_eci_enabled=True,
                        strict_eci_ok=False,
                        strict_eci_notes=["KeyUsage lipsă pe certificatul semnatar."],
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                    )

                eku_oids = _extract_eku_oids(signer_crypto)
                if ECI_REQUIRED_EKU_OIDS:
                    if not set(eku_oids).intersection(ECI_REQUIRED_EKU_OIDS):
                        return Result(
                            ok=False,
                            message="STRICT_ECI_EKU_FAIL",
                            signature_intact=intact,
                            signature_valid=valid,
                            signature_trusted=trusted,
                            coverage_entire_file=coverage_entire,
                            modification_none=modification_none,
                            signature_count=1,
                            signer_subject=signer_subject,
                            signer_issuer=signer_issuer,
                            signer_cert_sha256=signer_fp,
                            root_cert_sha256=root_fp,
                            sub_cert_sha256=sub_fp,
                            strict_issuer_enabled=strict_issuer,
                            hard_mode_enabled=hard_mode,
                            allow_fetching_enabled=allow_fetching,
                            revocation_mode=revocation_mode,
                            local_crl_enabled=bool(local_crls),
                            local_crl_count=len(local_crls or []),
                            strict_eci_enabled=True,
                            strict_eci_ok=False,
                            strict_eci_notes=["EKU nu corespunde politicii eCI."],
                            used_root_path=str(root_ca_path),
                            used_sub_path=str(sub_ca_path),
                        )
                else:
                    strict_eci_notes.append("EKU policy nedefinit (nu se aplică filtrare).")

                pol_oids = _extract_policy_oids(signer_crypto)
                if ECI_REQUIRED_POLICY_OIDS:
                    if not set(pol_oids).intersection(ECI_REQUIRED_POLICY_OIDS):
                        return Result(
                            ok=False,
                            message="STRICT_ECI_POLICY_FAIL",
                            signature_intact=intact,
                            signature_valid=valid,
                            signature_trusted=trusted,
                            coverage_entire_file=coverage_entire,
                            modification_none=modification_none,
                            signature_count=1,
                            signer_subject=signer_subject,
                            signer_issuer=signer_issuer,
                            signer_cert_sha256=signer_fp,
                            root_cert_sha256=root_fp,
                            sub_cert_sha256=sub_fp,
                            strict_issuer_enabled=strict_issuer,
                            hard_mode_enabled=hard_mode,
                            allow_fetching_enabled=allow_fetching,
                            revocation_mode=revocation_mode,
                            local_crl_enabled=bool(local_crls),
                            local_crl_count=len(local_crls or []),
                            strict_eci_enabled=True,
                            strict_eci_ok=False,
                            strict_eci_notes=["Policy OID nu corespunde eCI."],
                            used_root_path=str(root_ca_path),
                            used_sub_path=str(sub_ca_path),
                        )
                else:
                    strict_eci_notes.append("Policy OID nedefinit (nu se aplică filtrare).")

                strict_eci_ok = True

            # Hard mode (fail-closed if cannot parse /Contents)
            hard_ok: Optional[bool] = None
            hard_extras: Optional[List[str]] = None
            if hard_mode:
                if signer_fp is None:
                    return Result(
                        ok=False,
                        message="HARD_MODE_NO_SIGNER_CERT_EXTRACTED",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        signer_eku_oids=signer_eku_oids,
                        signer_policy_oids=signer_policy_oids,
                        signer_key_usage=signer_key_usage,
                        signer_not_before=signer_not_before,
                        signer_not_after=signer_not_after,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=True,
                        hard_mode_ok=False,
                        hard_mode_extra_certs=None,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        timestamp_check_enabled=require_timestamp,
                        timestamp_ok=timestamp_ok,
                        timestamp_info=timestamp_info,
                        timestamp_value=ts_value,
                        timestamp_tsa_subject=ts_tsa_subject,
                        content_timestamp_value=cts_value,
                        content_timestamp_tsa_subject=cts_tsa_subject,
                        strict_eci_enabled=strict_eci_enabled,
                        strict_eci_ok=strict_eci_ok,
                        strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                        details={"reason": "Cannot compute allowlist without signer cert fingerprint."},
                    )

                allowed = {root_fp, sub_fp, signer_fp}
                try:
                    hard_ok, hard_extras = _hard_mode_check(embedded_sig, allowed)
                except Exception as e:
                    return Result(
                        ok=False,
                        message=f"HARD_MODE_PARSE_FAILED: {type(e).__name__}: {e}",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        signer_eku_oids=signer_eku_oids,
                        signer_policy_oids=signer_policy_oids,
                        signer_key_usage=signer_key_usage,
                        signer_not_before=signer_not_before,
                        signer_not_after=signer_not_after,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=True,
                        hard_mode_ok=False,
                        hard_mode_extra_certs=None,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        timestamp_check_enabled=require_timestamp,
                        timestamp_ok=timestamp_ok,
                        timestamp_info=timestamp_info,
                        timestamp_value=ts_value,
                        timestamp_tsa_subject=ts_tsa_subject,
                        content_timestamp_value=cts_value,
                        content_timestamp_tsa_subject=cts_tsa_subject,
                        strict_eci_enabled=strict_eci_enabled,
                        strict_eci_ok=strict_eci_ok,
                        strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                        details={"reason": "Hard mode failed closed (cannot parse CMS in /Contents)."},
                    )

                if not hard_ok:
                    return Result(
                        ok=False,
                        message="HARD_MODE_EXTRA_EMBEDDED_CERTS_DETECTED",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        signer_eku_oids=signer_eku_oids,
                        signer_policy_oids=signer_policy_oids,
                        signer_key_usage=signer_key_usage,
                        signer_not_before=signer_not_before,
                        signer_not_after=signer_not_after,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=True,
                        hard_mode_ok=False,
                        hard_mode_extra_certs=hard_extras,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        timestamp_check_enabled=require_timestamp,
                        timestamp_ok=timestamp_ok,
                        timestamp_info=timestamp_info,
                        timestamp_value=ts_value,
                        timestamp_tsa_subject=ts_tsa_subject,
                        content_timestamp_value=cts_value,
                        content_timestamp_tsa_subject=cts_tsa_subject,
                        strict_eci_enabled=strict_eci_enabled,
                        strict_eci_ok=strict_eci_ok,
                        strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                        details={
                            "allowed_fingerprints": sorted(list(allowed)),
                            "extra_embedded_cert_fingerprints": hard_extras,
                            "note": "Hard mode rejects any CMS-embedded certificate not equal to Root/Sub/Signer.",
                        },
                    )

            # Strict issuer (true pin)
            expected_issuer = None
            actual_issuer = None
            strict_sig_ok: Optional[bool] = None
            strict_name_ok: Optional[bool] = None

            if strict_issuer:
                expected_issuer = sub_cert.subject.rfc4514_string()

                if signer_crypto is None:
                    return Result(
                        ok=False,
                        message="STRICT_ISSUER_NO_SIGNER_CERT_EXTRACTED",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=True,
                        strict_issuer_expected=expected_issuer,
                        strict_issuer_actual=None,
                        strict_issuer_verified_by_signature=None,
                        strict_issuer_name_match=None,
                        hard_mode_enabled=hard_mode,
                        hard_mode_ok=True if hard_mode else None,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        timestamp_check_enabled=require_timestamp,
                        timestamp_ok=timestamp_ok,
                        timestamp_info=timestamp_info,
                        timestamp_value=ts_value,
                        timestamp_tsa_subject=ts_tsa_subject,
                        content_timestamp_value=cts_value,
                        content_timestamp_tsa_subject=cts_tsa_subject,
                        strict_eci_enabled=strict_eci_enabled,
                        strict_eci_ok=strict_eci_ok,
                        strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                        details={"reason": "Could not extract/parse signing cert from PDF signature."},
                    )

                actual_issuer = signer_crypto.issuer.rfc4514_string()
                strict_name_ok = (signer_crypto.issuer == sub_cert.subject)
                strict_sig_ok = _verify_cert_issued_by(signer_crypto, sub_cert)

                if not strict_name_ok or not strict_sig_ok:
                    return Result(
                        ok=False,
                        message="STRICT_ISSUER_MISMATCH",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=True,
                        strict_issuer_expected=expected_issuer,
                        strict_issuer_actual=actual_issuer,
                        strict_issuer_verified_by_signature=bool(strict_sig_ok),
                        strict_issuer_name_match=bool(strict_name_ok),
                        hard_mode_enabled=hard_mode,
                        hard_mode_ok=True if hard_mode else None,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        timestamp_check_enabled=require_timestamp,
                        timestamp_ok=timestamp_ok,
                        timestamp_info=timestamp_info,
                        timestamp_value=ts_value,
                        timestamp_tsa_subject=ts_tsa_subject,
                        content_timestamp_value=cts_value,
                        content_timestamp_tsa_subject=cts_tsa_subject,
                        strict_eci_enabled=strict_eci_enabled,
                        strict_eci_ok=strict_eci_ok,
                        strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                        details={
                            "expected_sub_subject_rfc4514": expected_issuer,
                            "actual_signer_issuer_rfc4514": actual_issuer,
                            "issuer_name_match": bool(strict_name_ok),
                            "issuer_signature_verified": bool(strict_sig_ok),
                        },
                    )

            ok = intact and valid and trusted and coverage_entire and modification_none
            if require_timestamp:
                ok = ok and (timestamp_ok is True)
            if strict_eci_enabled:
                ok = ok and (strict_eci_ok is True)

            if ok:
                msg = "OK"
            else:
                if require_timestamp and timestamp_ok is False:
                    msg = "TIMESTAMP_REQUIRED_FAILED"
                elif strict_eci_enabled and strict_eci_ok is False:
                    msg = "STRICT_ECI_FAILED"
                elif not intact:
                    msg = "INTEGRITY_FAILED"
                elif not valid:
                    msg = "CRYPTO_SIGNATURE_INVALID"
                elif not trusted:
                    msg = "CHAIN_VALIDATION_FAILED"
                elif not coverage_entire:
                    msg = "COVERAGE_NOT_ENTIRE_FILE"
                elif not modification_none:
                    msg = "MODIFICATIONS_DETECTED"
                else:
                    msg = "SIGNATURE_OR_POLICY_VALIDATION_FAILED"

            summary = {
                "intact": intact,
                "valid": valid,
                "trusted": trusted,
                "coverage": str(coverage),
                "modification_level": str(modification_level),
                "coverage_entire_file": coverage_entire,
                "modification_none": modification_none,
                "allow_fetching": bool(allow_fetching),
                "revocation_mode": str(revocation_mode),
                "strict_issuer_enabled": bool(strict_issuer),
                "hard_mode_enabled": bool(hard_mode),
                "strict_eci_enabled": bool(strict_eci_enabled),
                "timestamp_required": bool(require_timestamp),
                "timestamp_ok": bool(timestamp_ok) if timestamp_ok is not None else None,
            }

            return Result(
                ok=ok,
                message=msg,
                signature_intact=intact,
                signature_valid=valid,
                signature_trusted=trusted,
                coverage_entire_file=coverage_entire,
                modification_none=modification_none,
                signature_count=1,
                signer_subject=signer_subject,
                signer_issuer=signer_issuer,
                signer_cert_sha256=signer_fp,
                signer_eku_oids=signer_eku_oids,
                signer_policy_oids=signer_policy_oids,
                signer_key_usage=signer_key_usage,
                signer_not_before=signer_not_before,
                signer_not_after=signer_not_after,
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=bool(strict_issuer),
                strict_issuer_expected=expected_issuer,
                strict_issuer_actual=actual_issuer,
                strict_issuer_verified_by_signature=strict_sig_ok,
                strict_issuer_name_match=strict_name_ok,
                hard_mode_enabled=bool(hard_mode),
                hard_mode_ok=True if hard_mode else None,
                hard_mode_extra_certs=hard_extras if hard_mode else None,
                allow_fetching_enabled=bool(allow_fetching),
                revocation_mode=str(revocation_mode),
                local_crl_enabled=bool(local_crls),
                local_crl_count=len(local_crls or []),
                timestamp_check_enabled=bool(require_timestamp),
                timestamp_ok=timestamp_ok,
                timestamp_info=timestamp_info,
                timestamp_value=ts_value,
                timestamp_tsa_subject=ts_tsa_subject,
                content_timestamp_value=cts_value,
                content_timestamp_tsa_subject=cts_tsa_subject,
                strict_eci_enabled=bool(strict_eci_enabled),
                strict_eci_ok=strict_eci_ok,
                strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                used_root_path=str(root_ca_path),
                used_sub_path=str(sub_ca_path),
                details=summary,
            )

    except Exception as e:
        return Result(
            ok=False,
            message=f"EXCEPTION: {type(e).__name__}: {e}",
            signature_count=0,
            strict_issuer_enabled=bool(strict_issuer),
            hard_mode_enabled=bool(hard_mode),
            allow_fetching_enabled=bool(allow_fetching),
            revocation_mode=str(revocation_mode),
            local_crl_enabled=bool(local_crls),
            local_crl_count=len(local_crls or []),
            timestamp_check_enabled=bool(require_timestamp),
            timestamp_ok=None,
            timestamp_info=None,
            timestamp_value=None,
            timestamp_tsa_subject=None,
            content_timestamp_value=None,
            content_timestamp_tsa_subject=None,
            strict_eci_enabled=bool(strict_eci),
            used_root_path=str(root_ca_path),
            used_sub_path=str(sub_ca_path),
        )


# =============================================================================
# Signature validation helper (multi-signature aware)
# =============================================================================
def validate_embedded_signature_against_two_cas(
    embedded_sig: Any,
    signature_count: int,
    root_cert: x509.Certificate,
    sub_cert: x509.Certificate,
    root_fp: str,
    sub_fp: str,
    allow_fetching: bool,
    revocation_mode: str,
    strict_issuer: bool,
    hard_mode: bool,
    strict_eci: bool,
    local_crls: Optional[List[bytes]],
    require_timestamp: bool,
    root_ca_path: Path,
    sub_ca_path: Path,
) -> Result:
    strict_eci_enabled = bool(strict_eci)
    strict_eci_notes: List[str] = []

    vc = ValidationContext(
        trust_roots=[_to_asn1(root_cert)],
        other_certs=[_to_asn1(sub_cert)],
        allow_fetching=allow_fetching,
        revocation_mode=revocation_mode,
        crls=local_crls,
    )

    try:
        status = validate_pdf_signature(embedded_sig, vc)

        intact = bool(getattr(status, "intact", False))
        valid = bool(getattr(status, "valid", False))
        trusted = bool(getattr(status, "trusted", False))
        ts_validity = getattr(status, "timestamp_validity", None)
        content_ts_validity = getattr(status, "content_timestamp_validity", None)
        timestamp_ok: Optional[bool] = None
        timestamp_info: Optional[str] = None
        ts_value: Optional[str] = None
        ts_tsa_subject: Optional[str] = None
        cts_value: Optional[str] = None
        cts_tsa_subject: Optional[str] = None
        if ts_validity is not None:
            try:
                ts_value = ts_validity.timestamp.isoformat()
            except Exception:
                ts_value = None
            try:
                ts_tsa_subject = ts_validity.signing_cert.subject.human_friendly
            except Exception:
                ts_tsa_subject = None
        if content_ts_validity is not None:
            try:
                cts_value = content_ts_validity.timestamp.isoformat()
            except Exception:
                cts_value = None
            try:
                cts_tsa_subject = content_ts_validity.signing_cert.subject.human_friendly
            except Exception:
                cts_tsa_subject = None
        if require_timestamp:
            any_ts = ts_validity or content_ts_validity
            if any_ts is None:
                timestamp_ok = False
                timestamp_info = "Nu există timestamp validabil în semnătură."
            else:
                ok_list = []
                if ts_validity is not None:
                    ok_list.append(bool(ts_validity.valid and ts_validity.intact and ts_validity.trusted))
                if content_ts_validity is not None:
                    ok_list.append(
                        bool(content_ts_validity.valid and content_ts_validity.intact and content_ts_validity.trusted)
                    )
                timestamp_ok = any(ok_list)
                timestamp_info = "Timestamp valid și de încredere." if timestamp_ok else "Timestamp prezent dar invalid."

        coverage = getattr(status, "coverage", None)
        modification_level = getattr(status, "modification_level", None)

        coverage_entire = _is_entire_file_coverage(coverage)
        modification_none = _is_modification_none(modification_level)

        # Extract signer cert
        signer_asn1 = None
        signer_crypto: Optional[x509.Certificate] = None
        signer_subject = None
        signer_issuer = None
        signer_fp = None
        signer_eku_oids: Optional[List[str]] = None
        signer_policy_oids: Optional[List[str]] = None
        signer_key_usage: Optional[str] = None
        signer_not_before: Optional[str] = None
        signer_not_after: Optional[str] = None

        try:
            signer_asn1 = status.signing_cert
        except Exception:
            signer_asn1 = None

        if signer_asn1 is not None:
            try:
                signer_subject = signer_asn1.subject.human_friendly
                signer_issuer = signer_asn1.issuer.human_friendly
                signer_fp = hashlib.sha256(signer_asn1.dump()).hexdigest()
                signer_crypto = x509.load_der_x509_certificate(signer_asn1.dump())
            except Exception:
                signer_crypto = None

        if signer_crypto is not None:
            try:
                signer_key_usage = str(
                    signer_crypto.extensions.get_extension_for_class(x509.KeyUsage).value
                )
            except Exception:
                signer_key_usage = None
            signer_eku_oids = _extract_eku_oids(signer_crypto)
            signer_policy_oids = _extract_policy_oids(signer_crypto)
            try:
                signer_not_before = signer_crypto.not_valid_before.isoformat()
                signer_not_after = signer_crypto.not_valid_after.isoformat()
            except Exception:
                signer_not_before = None
                signer_not_after = None

        # Strict eCI checks (fail-closed)
        strict_eci_ok: Optional[bool] = None
        if strict_eci_enabled:
            if signer_crypto is None:
                return Result(
                    ok=False,
                    message="STRICT_ECI_NO_SIGNER_CERT",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    signer_eku_oids=signer_eku_oids,
                    signer_policy_oids=signer_policy_oids,
                    signer_key_usage=signer_key_usage,
                    signer_not_before=signer_not_before,
                    signer_not_after=signer_not_after,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=hard_mode,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    strict_eci_enabled=True,
                    strict_eci_ok=False,
                    strict_eci_notes=["Nu pot extrage certificatul semnatarului."],
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                )

            # Key usage check
            try:
                ku = signer_crypto.extensions.get_extension_for_class(x509.KeyUsage).value
                if not (ku.digital_signature or ku.content_commitment):
                    return Result(
                        ok=False,
                        message="STRICT_ECI_KEY_USAGE_FAIL",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=signature_count,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=hard_mode,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        strict_eci_enabled=True,
                        strict_eci_ok=False,
                        strict_eci_notes=["KeyUsage nu include digitalSignature/contentCommitment."],
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                    )
            except Exception:
                return Result(
                    ok=False,
                    message="STRICT_ECI_KEY_USAGE_MISSING",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    signer_eku_oids=signer_eku_oids,
                    signer_policy_oids=signer_policy_oids,
                    signer_key_usage=signer_key_usage,
                    signer_not_before=signer_not_before,
                    signer_not_after=signer_not_after,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=hard_mode,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    strict_eci_enabled=True,
                    strict_eci_ok=False,
                    strict_eci_notes=["KeyUsage lipsă pe certificatul semnatar."],
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                )

            eku_oids = _extract_eku_oids(signer_crypto)
            if ECI_REQUIRED_EKU_OIDS:
                if not set(eku_oids).intersection(ECI_REQUIRED_EKU_OIDS):
                    return Result(
                        ok=False,
                        message="STRICT_ECI_EKU_FAIL",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=signature_count,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=hard_mode,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        strict_eci_enabled=True,
                        strict_eci_ok=False,
                        strict_eci_notes=["EKU nu corespunde politicii eCI."],
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                    )
            else:
                strict_eci_notes.append("EKU policy nedefinit (nu se aplică filtrare).")

            pol_oids = _extract_policy_oids(signer_crypto)
            if ECI_REQUIRED_POLICY_OIDS:
                if not set(pol_oids).intersection(ECI_REQUIRED_POLICY_OIDS):
                    return Result(
                        ok=False,
                        message="STRICT_ECI_POLICY_FAIL",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        coverage_entire_file=coverage_entire,
                        modification_none=modification_none,
                        signature_count=signature_count,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=strict_issuer,
                        hard_mode_enabled=hard_mode,
                        allow_fetching_enabled=allow_fetching,
                        revocation_mode=revocation_mode,
                        local_crl_enabled=bool(local_crls),
                        local_crl_count=len(local_crls or []),
                        strict_eci_enabled=True,
                        strict_eci_ok=False,
                        strict_eci_notes=["Policy OID nu corespunde eCI."],
                        used_root_path=str(root_ca_path),
                        used_sub_path=str(sub_ca_path),
                    )
            else:
                strict_eci_notes.append("Policy OID nedefinit (nu se aplică filtrare).")

            strict_eci_ok = True

        # Hard mode (fail-closed if cannot parse /Contents)
        hard_ok: Optional[bool] = None
        hard_extras: Optional[List[str]] = None
        if hard_mode:
            if signer_fp is None:
                return Result(
                    ok=False,
                    message="HARD_MODE_NO_SIGNER_CERT_EXTRACTED",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    signer_eku_oids=signer_eku_oids,
                    signer_policy_oids=signer_policy_oids,
                    signer_key_usage=signer_key_usage,
                    signer_not_before=signer_not_before,
                    signer_not_after=signer_not_after,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=True,
                    hard_mode_ok=False,
                    hard_mode_extra_certs=None,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=require_timestamp,
                    timestamp_ok=timestamp_ok,
                    timestamp_info=timestamp_info,
                    timestamp_value=ts_value,
                    timestamp_tsa_subject=ts_tsa_subject,
                    content_timestamp_value=cts_value,
                    content_timestamp_tsa_subject=cts_tsa_subject,
                    strict_eci_enabled=strict_eci_enabled,
                    strict_eci_ok=strict_eci_ok,
                    strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                    details={"reason": "Cannot compute allowlist without signer cert fingerprint."},
                )

            allowed = {root_fp, sub_fp, signer_fp}
            try:
                hard_ok, hard_extras = _hard_mode_check(embedded_sig, allowed)
            except Exception as e:
                return Result(
                    ok=False,
                    message=f"HARD_MODE_PARSE_FAILED: {type(e).__name__}: {e}",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    signer_eku_oids=signer_eku_oids,
                    signer_policy_oids=signer_policy_oids,
                    signer_key_usage=signer_key_usage,
                    signer_not_before=signer_not_before,
                    signer_not_after=signer_not_after,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=True,
                    hard_mode_ok=False,
                    hard_mode_extra_certs=None,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=require_timestamp,
                    timestamp_ok=timestamp_ok,
                    timestamp_info=timestamp_info,
                    timestamp_value=ts_value,
                    timestamp_tsa_subject=ts_tsa_subject,
                    content_timestamp_value=cts_value,
                    content_timestamp_tsa_subject=cts_tsa_subject,
                    strict_eci_enabled=strict_eci_enabled,
                    strict_eci_ok=strict_eci_ok,
                    strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                    details={"reason": "Hard mode failed closed (cannot parse CMS in /Contents)."},
                )

            if not hard_ok:
                return Result(
                    ok=False,
                    message="HARD_MODE_EXTRA_EMBEDDED_CERTS_DETECTED",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    signer_eku_oids=signer_eku_oids,
                    signer_policy_oids=signer_policy_oids,
                    signer_key_usage=signer_key_usage,
                    signer_not_before=signer_not_before,
                    signer_not_after=signer_not_after,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                    hard_mode_enabled=True,
                    hard_mode_ok=False,
                    hard_mode_extra_certs=hard_extras,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=require_timestamp,
                    timestamp_ok=timestamp_ok,
                    timestamp_info=timestamp_info,
                    timestamp_value=ts_value,
                    timestamp_tsa_subject=ts_tsa_subject,
                    content_timestamp_value=cts_value,
                    content_timestamp_tsa_subject=cts_tsa_subject,
                    strict_eci_enabled=strict_eci_enabled,
                    strict_eci_ok=strict_eci_ok,
                    strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                    details={
                        "allowed_fingerprints": sorted(list(allowed)),
                        "extra_embedded_cert_fingerprints": hard_extras,
                        "note": "Hard mode rejects any CMS-embedded certificate not equal to Root/Sub/Signer.",
                    },
                )

        # Strict issuer (true pin)
        expected_issuer = None
        actual_issuer = None
        strict_sig_ok: Optional[bool] = None
        strict_name_ok: Optional[bool] = None

        if strict_issuer:
            expected_issuer = sub_cert.subject.rfc4514_string()

            if signer_crypto is None:
                return Result(
                    ok=False,
                    message="STRICT_ISSUER_NO_SIGNER_CERT_EXTRACTED",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=True,
                    strict_issuer_expected=expected_issuer,
                    strict_issuer_actual=None,
                    strict_issuer_verified_by_signature=None,
                    strict_issuer_name_match=None,
                    hard_mode_enabled=hard_mode,
                    hard_mode_ok=True if hard_mode else None,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=require_timestamp,
                    timestamp_ok=timestamp_ok,
                    timestamp_info=timestamp_info,
                    timestamp_value=ts_value,
                    timestamp_tsa_subject=ts_tsa_subject,
                    content_timestamp_value=cts_value,
                    content_timestamp_tsa_subject=cts_tsa_subject,
                    strict_eci_enabled=strict_eci_enabled,
                    strict_eci_ok=strict_eci_ok,
                    strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                    details={"reason": "Could not extract/parse signing cert from PDF signature."},
                )

            actual_issuer = signer_crypto.issuer.rfc4514_string()
            strict_name_ok = (signer_crypto.issuer == sub_cert.subject)
            strict_sig_ok = _verify_cert_issued_by(signer_crypto, sub_cert)

            if not strict_name_ok or not strict_sig_ok:
                return Result(
                    ok=False,
                    message="STRICT_ISSUER_MISMATCH",
                    signature_intact=intact,
                    signature_valid=valid,
                    signature_trusted=trusted,
                    coverage_entire_file=coverage_entire,
                    modification_none=modification_none,
                    signature_count=signature_count,
                    signer_subject=signer_subject,
                    signer_issuer=signer_issuer,
                    signer_cert_sha256=signer_fp,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=True,
                    strict_issuer_expected=expected_issuer,
                    strict_issuer_actual=actual_issuer,
                    strict_issuer_verified_by_signature=bool(strict_sig_ok),
                    strict_issuer_name_match=bool(strict_name_ok),
                    hard_mode_enabled=hard_mode,
                    hard_mode_ok=True if hard_mode else None,
                    allow_fetching_enabled=allow_fetching,
                    revocation_mode=revocation_mode,
                    local_crl_enabled=bool(local_crls),
                    local_crl_count=len(local_crls or []),
                    timestamp_check_enabled=require_timestamp,
                    timestamp_ok=timestamp_ok,
                    timestamp_info=timestamp_info,
                    timestamp_value=ts_value,
                    timestamp_tsa_subject=ts_tsa_subject,
                    content_timestamp_value=cts_value,
                    content_timestamp_tsa_subject=cts_tsa_subject,
                    strict_eci_enabled=strict_eci_enabled,
                    strict_eci_ok=strict_eci_ok,
                    strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
                    used_root_path=str(root_ca_path),
                    used_sub_path=str(sub_ca_path),
                    details={
                        "expected_sub_subject_rfc4514": expected_issuer,
                        "actual_signer_issuer_rfc4514": actual_issuer,
                        "issuer_name_match": bool(strict_name_ok),
                        "issuer_signature_verified": bool(strict_sig_ok),
                    },
                )

        ok = intact and valid and trusted and coverage_entire and modification_none
        if require_timestamp:
            ok = ok and (timestamp_ok is True)
        if strict_eci_enabled:
            ok = ok and (strict_eci_ok is True)

        if ok:
            msg = "OK"
        else:
            if require_timestamp and timestamp_ok is False:
                msg = "TIMESTAMP_REQUIRED_FAILED"
            elif strict_eci_enabled and strict_eci_ok is False:
                msg = "STRICT_ECI_FAILED"
            elif not intact:
                msg = "INTEGRITY_FAILED"
            elif not valid:
                msg = "CRYPTO_SIGNATURE_INVALID"
            elif not trusted:
                msg = "CHAIN_VALIDATION_FAILED"
            elif not coverage_entire:
                msg = "COVERAGE_NOT_ENTIRE_FILE"
            elif not modification_none:
                msg = "MODIFICATIONS_DETECTED"
            else:
                msg = "SIGNATURE_OR_POLICY_VALIDATION_FAILED"

        summary = {
            "intact": intact,
            "valid": valid,
            "trusted": trusted,
            "coverage": str(coverage),
            "modification_level": str(modification_level),
            "coverage_entire_file": coverage_entire,
            "modification_none": modification_none,
            "allow_fetching": bool(allow_fetching),
            "revocation_mode": str(revocation_mode),
            "strict_issuer_enabled": bool(strict_issuer),
            "hard_mode_enabled": bool(hard_mode),
            "strict_eci_enabled": bool(strict_eci_enabled),
            "timestamp_required": bool(require_timestamp),
            "timestamp_ok": bool(timestamp_ok) if timestamp_ok is not None else None,
        }

        return Result(
            ok=ok,
            message=msg,
            signature_intact=intact,
            signature_valid=valid,
            signature_trusted=trusted,
            coverage_entire_file=coverage_entire,
            modification_none=modification_none,
            signature_count=signature_count,
            signer_subject=signer_subject,
            signer_issuer=signer_issuer,
            signer_cert_sha256=signer_fp,
            signer_eku_oids=signer_eku_oids,
            signer_policy_oids=signer_policy_oids,
            signer_key_usage=signer_key_usage,
            signer_not_before=signer_not_before,
            signer_not_after=signer_not_after,
            root_cert_sha256=root_fp,
            sub_cert_sha256=sub_fp,
            strict_issuer_enabled=bool(strict_issuer),
            strict_issuer_expected=expected_issuer,
            strict_issuer_actual=actual_issuer,
            strict_issuer_verified_by_signature=strict_sig_ok,
            strict_issuer_name_match=strict_name_ok,
            hard_mode_enabled=bool(hard_mode),
            hard_mode_ok=True if hard_mode else None,
            hard_mode_extra_certs=hard_extras if hard_mode else None,
            allow_fetching_enabled=bool(allow_fetching),
            revocation_mode=str(revocation_mode),
            local_crl_enabled=bool(local_crls),
            local_crl_count=len(local_crls or []),
            timestamp_check_enabled=bool(require_timestamp),
            timestamp_ok=timestamp_ok,
            timestamp_info=timestamp_info,
            timestamp_value=ts_value,
            timestamp_tsa_subject=ts_tsa_subject,
            content_timestamp_value=cts_value,
            content_timestamp_tsa_subject=cts_tsa_subject,
            strict_eci_enabled=bool(strict_eci_enabled),
            strict_eci_ok=strict_eci_ok,
            strict_eci_notes=strict_eci_notes if strict_eci_enabled else None,
            used_root_path=str(root_ca_path),
            used_sub_path=str(sub_ca_path),
            details=summary,
        )
    except Exception as e:
        return Result(
            ok=False,
            message=f"EXCEPTION: {type(e).__name__}: {e}",
            signature_count=signature_count,
            strict_issuer_enabled=bool(strict_issuer),
            hard_mode_enabled=bool(hard_mode),
            allow_fetching_enabled=bool(allow_fetching),
            revocation_mode=str(revocation_mode),
            local_crl_enabled=bool(local_crls),
            local_crl_count=len(local_crls or []),
            timestamp_check_enabled=bool(require_timestamp),
            timestamp_ok=None,
            timestamp_info=None,
            timestamp_value=None,
            timestamp_tsa_subject=None,
            content_timestamp_value=None,
            content_timestamp_tsa_subject=None,
            strict_eci_enabled=bool(strict_eci),
            used_root_path=str(root_ca_path),
            used_sub_path=str(sub_ca_path),
        )


# =============================================================================
# Report export
# =============================================================================
def export_report(pdf_path: Path, res: Result) -> Tuple[Path, Path]:
    """
    Writes:
      - <PDFNAME>.validare.<timestamp>.txt
      - <PDFNAME>.validare.<timestamp>.json
    next to the PDF, returns (txt_path, json_path).
    """
    stamp = now_stamp_local()
    base = pdf_path.with_suffix("")  # removes .pdf
    txt_path = Path(str(base) + f".validare.{stamp}.txt")
    json_path = Path(str(base) + f".validare.{stamp}.json")

    txt_path.write_text(result_to_human(res) + "\n", encoding="utf-8")
    json_path.write_text(result_to_json(res) + "\n", encoding="utf-8")
    return txt_path, json_path
# =============================================================================
# UI widgets: Tooltip
# =============================================================================
class ToolTip:
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _e=None):
        if self.tip is not None:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 25
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        frm = ttk.Frame(self.tip, padding=8)
        frm.pack()
        lbl = ttk.Label(frm, text=self.text, justify="left", wraplength=520)
        lbl.pack()

    def _hide(self, _e=None):
        if self.tip is not None:
            self.tip.destroy()
            self.tip = None


# =============================================================================
# GUI
# =============================================================================
def run_gui() -> int:
    if tk is None or ttk is None or ScrolledText is None:
        print("GUI unavailable (tkinter not present). Use CLI mode.", file=sys.stderr)
        return 3

    root = tk.Tk()
    root.withdraw()
    try:
        root.iconbitmap(resource_path("assets/app.ico"))
    except Exception:
        pass

    root.title(f"{APP_NAME} v{APP_VERSION}")
    root.geometry("1020x760")
    root.minsize(920, 660)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    try:
        style.configure("TButton", padding=7)
        style.configure("TLabelframe", padding=10)
        style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Muted.TLabel", foreground="#666666")
        style.configure("Link.TLabel", foreground="#1a73e8", font=("Segoe UI", 9, "underline"))
        style.configure("StatusGood.TLabel", foreground="#1b5e20", font=("Segoe UI", 14, "bold"))
        style.configure("StatusWarn.TLabel", foreground="#e65100", font=("Segoe UI", 14, "bold"))
        style.configure("StatusBad.TLabel", foreground="#b71c1c", font=("Segoe UI", 14, "bold"))
    except Exception:
        pass

    # Menu: About
    menubar = tk.Menu(root)
    helpmenu = tk.Menu(menubar, tearoff=0)

    def show_about():
        lines = [
            f"{APP_NAME} v{APP_VERSION} (build {APP_BUILD})",
            f"{APP_AUTHOR}",
            "",
            "Changelog:",
        ]
        for v, t in APP_CHANGELOG:
            lines.append(f"• {v}: {t}")
        lines.append("")
        messagebox.showinfo("About", "\n".join(lines))

    helpmenu.add_command(label="About", command=show_about)
    menubar.add_cascade(label="Help", menu=helpmenu)
    root.config(menu=menubar)

    # State vars
    pdf_var = tk.StringVar(value="")

    # Certificate paths (manual selection).
    root_override_var = tk.StringVar(value="")
    sub_override_var = tk.StringVar(value="")
    cert_source_var = tk.StringVar(value="bundled")

    allow_fetch_var = tk.BooleanVar(value=False)
    revocation_mode_var = tk.StringVar(value="soft-fail")
    local_crl_var = tk.BooleanVar(value=False)
    timestamp_check_var = tk.BooleanVar(value=False)
    strict_issuer_var = tk.BooleanVar(value=False)
    hard_mode_var = tk.BooleanVar(value=False)
    strict_eci_var = tk.BooleanVar(value=False)

    def pick_pdf():
        p = filedialog.askopenfilename(
            title="Selectează document PDF semnat",
            filetypes=[("Documente PDF", "*.pdf"), ("Toate", "*.*")],
        )
        if p:
            pdf_var.set(p)

    def pick_root():
        p = filedialog.askopenfilename(
            title="Selectează certificatul Root CA (.cer/.crt/.pem)",
            filetypes=[("Cert", "*.cer *.crt *.pem *.der"), ("Toate", "*.*")],
        )
        if p:
            root_override_var.set(p)
            refresh_cert_ui()

    def pick_sub():
        p = filedialog.askopenfilename(
            title="Selectează certificatul Sub/Intermediate CA (.cer/.crt/.pem)",
            filetypes=[("Cert", "*.cer *.crt *.pem *.der"), ("Toate", "*.*")],
        )
        if p:
            sub_override_var.set(p)
            refresh_cert_ui()

    def bundled_cert_paths() -> Tuple[Path, Path]:
        return (
            resource_path("assets/certs/ro_cei_mai_root-ca.cer"),
            resource_path("assets/certs/ro_cei_mai_sub-ca.cer"),
        )

    def resolve_cert_paths() -> Tuple[Optional[Path], Optional[Path]]:
        if cert_source_var.get() == "bundled":
            root_path, sub_path = bundled_cert_paths()
        else:
            root_path = Path(root_override_var.get()).expanduser() if root_override_var.get().strip() else None
            sub_path = Path(sub_override_var.get()).expanduser() if sub_override_var.get().strip() else None

        if root_path is not None and not root_path.exists():
            root_path = None
        if sub_path is not None and not sub_path.exists():
            sub_path = None

        return root_path, sub_path

    def load_local_crls() -> List[bytes]:
        crls: List[bytes] = []
        crl_dir = resource_path("assets/certs")
        if crl_dir.exists():
            for p in sorted(crl_dir.rglob("*.crl")):
                try:
                    crls.append(p.read_bytes())
                except Exception:
                    continue
        return crls

    # Layout
    container = ttk.Frame(root, padding=16)
    container.pack(fill="both", expand=True)

    # Header
    header = ttk.Frame(container)
    header.pack(fill="x", pady=(0, 10))

    try:
        logo_img = Image.open(resource_path("assets/logo.png")).convert("RGBA")
        logo_img = logo_img.resize((84, 84))
        logo = ImageTk.PhotoImage(logo_img)
        logo_label = ttk.Label(header, image=logo)
        logo_label.image = logo
        logo_label.pack(side="left", padx=(0, 14))
    except Exception:
        pass

    title_block = ttk.Frame(header)
    title_block.pack(side="left", fill="x", expand=True)

    def make_link_label(parent: tk.Widget, text: str, url: str) -> ttk.Label:
        lbl = ttk.Label(parent, text=text, style="Link.TLabel", cursor="hand2")
        lbl.bind("<Button-1>", lambda _e: open_url(url))
        return lbl

    ttk.Label(title_block, text=APP_NAME, style="Header.TLabel").pack(anchor="w")
    meta_line = ttk.Frame(title_block)
    meta_line.pack(anchor="w", pady=(4, 0))
    ttk.Label(meta_line, text=f"v{APP_VERSION} • build {APP_BUILD} • ", style="Muted.TLabel").pack(side="left")
    make_link_label(meta_line, "vlah.io", "https://vlah.io").pack(side="left")
    ttk.Label(meta_line, text=" • ", style="Muted.TLabel").pack(side="left")
    make_link_label(meta_line, "@24vlh", "https://github.com/24vlh").pack(side="left")

    status_label = ttk.Label(header, text="—", style="Muted.TLabel")
    status_label.pack(side="right", anchor="e")

    def update_status(ok: Optional[bool], msg: str):
        if ok is True:
            status_label.configure(text=msg, style="StatusGood.TLabel")
        elif ok is False:
            status_label.configure(text=msg, style="StatusBad.TLabel")
        else:
            status_label.configure(text=msg, style="Muted.TLabel")

    # Main columns
    body = ttk.Frame(container)
    body.pack(fill="both", expand=True)
    body.columnconfigure(0, weight=1, uniform="cols")
    body.columnconfigure(1, weight=1, uniform="cols")
    body.rowconfigure(0, weight=1)

    left_col = ttk.Frame(body)
    left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
    left_col.rowconfigure(0, weight=1)
    left_col.columnconfigure(0, weight=1)

    left_canvas = tk.Canvas(left_col, highlightthickness=0)
    left_canvas.grid(row=0, column=0, sticky="nsew")
    left_scroll = ttk.Scrollbar(left_col, orient="vertical", command=left_canvas.yview)
    left_scroll.grid(row=0, column=1, sticky="ns")
    left_canvas.configure(yscrollcommand=left_scroll.set)

    left_inner = ttk.Frame(left_canvas)
    left_inner_id = left_canvas.create_window((0, 0), window=left_inner, anchor="nw")

    def _sync_left_width(_e=None):
        left_canvas.itemconfigure(left_inner_id, width=left_canvas.winfo_width())

    def _sync_left_scroll(_e=None):
        left_canvas.configure(scrollregion=left_canvas.bbox("all"))

    left_canvas.bind("<Configure>", _sync_left_width)
    left_inner.bind("<Configure>", _sync_left_scroll)

    def _on_left_mousewheel(event):
        try:
            widget = root.winfo_containing(root.winfo_pointerx(), root.winfo_pointery())
            if widget is None:
                return
            if widget != left_canvas and not str(widget).startswith(str(left_inner)):
                return
        except Exception:
            return
        if event.delta:
            left_canvas.yview_scroll(int(-event.delta / 120), "units")
        else:
            if event.num == 4:
                left_canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                left_canvas.yview_scroll(1, "units")

    root.bind_all("<MouseWheel>", _on_left_mousewheel)
    root.bind_all("<Button-4>", _on_left_mousewheel)
    root.bind_all("<Button-5>", _on_left_mousewheel)

    right_col = ttk.Frame(body)
    right_col.grid(row=0, column=1, sticky="nsew")

    # Files group
    files_header = ttk.Frame(left_inner)
    ttk.Label(files_header, text="Fișiere", font=("Segoe UI", 10, "bold")).pack(side="left")
    files_header_spacer = ttk.Frame(files_header)
    files_header_spacer.pack(side="left", fill="x", expand=True)
    info_bundle = ttk.Label(files_header, text="ⓘ", style="Muted.TLabel", cursor="question_arrow")
    info_bundle.pack(side="left", padx=(6, 4))
    ToolTip(info_bundle, "Certificatele incluse sunt în assets/certs/ (Root/Sub MAI).")
    make_link_label(
        files_header,
        "Descarcă MAI (Root/Sub)",
        "https://hub.mai.gov.ro/cei/info/descarca-cert",
    ).pack(side="left")
    files = ttk.LabelFrame(left_inner, labelwidget=files_header, padding=12)
    files.pack(fill="x", pady=(0, 10))

    def _cert_fp_text(p: Optional[Path]) -> str:
        if p is None:
            return "UNKNOWN"
        try:
            cert = _load_cert_any(p)
            return _cert_sha256_der(cert)
        except Exception:
            return "UNKNOWN"

    def refresh_cert_ui():
        root_path, sub_path = resolve_cert_paths()
        root_fp = _cert_fp_text(root_path)
        sub_fp = _cert_fp_text(sub_path)
        root_fp_label.configure(text=f"Root SHA256: {root_fp}")
        sub_fp_label.configure(text=f"Sub  SHA256: {sub_fp}")
        try:
            root_fp_tooltip.text = f"Root SHA256: {root_fp}"
        except Exception:
            pass
        try:
            sub_fp_tooltip.text = f"Sub  SHA256: {sub_fp}"
        except Exception:
            pass

    def refresh_cert_source():
        if cert_source_var.get() == "bundled":
            root_path, sub_path = bundled_cert_paths()
            root_override_var.set(str(root_path))
            sub_override_var.set(str(sub_path))
            ent_root.configure(state="disabled")
            ent_sub.configure(state="disabled")
            btn_root.configure(state="disabled")
            btn_sub.configure(state="disabled")
        else:
            ent_root.configure(state="normal")
            ent_sub.configure(state="normal")
            btn_root.configure(state="normal")
            btn_sub.configure(state="normal")
        refresh_cert_ui()

    # Source row
    row_source = ttk.Frame(files)
    row_source.pack(fill="x", pady=(2, 8))
    ttk.Label(row_source, text="Certificate", width=10).pack(side="left")
    src_bundled = ttk.Radiobutton(
        row_source,
        text="Folosește certificate MAI incluse",
        variable=cert_source_var,
        value="bundled",
        command=refresh_cert_source,
    )
    src_bundled.pack(side="left", padx=(0, 10))
    src_manual = ttk.Radiobutton(
        row_source,
        text="Selectează manual",
        variable=cert_source_var,
        value="manual",
        command=refresh_cert_source,
    )
    src_manual.pack(side="left")
    # PDF row (always)
    row_pdf = ttk.Frame(files)
    row_pdf.pack(fill="x", pady=6)
    ttk.Label(row_pdf, text="PDF", width=10).pack(side="left")
    ent_pdf = ttk.Entry(row_pdf, textvariable=pdf_var)
    ent_pdf.pack(side="left", fill="x", expand=True, padx=8)
    btn_pdf = ttk.Button(row_pdf, text="Browse…", command=pick_pdf, width=12)
    btn_pdf.pack(side="left")
    info_pdf = ttk.Label(row_pdf, text="ⓘ", style="Muted.TLabel", cursor="question_arrow")
    info_pdf.pack(side="left", padx=(6, 0))
    ToolTip(info_pdf, "Alege PDF-ul semnat.")

    # Root row
    row_root = ttk.Frame(files)
    row_root.pack(fill="x", pady=6)
    ttk.Label(row_root, text="Root CA", width=10).pack(side="left")
    ent_root = ttk.Entry(row_root, textvariable=root_override_var)
    ent_root.pack(side="left", fill="x", expand=True, padx=2)
    fp_root_icon = ttk.Label(row_root, text="🔒", style="Muted.TLabel", cursor="question_arrow")
    fp_root_icon.pack(side="left", padx=(0, 2))
    root_fp_tooltip = ToolTip(fp_root_icon, "Root SHA256: UNKNOWN")
    btn_root = ttk.Button(row_root, text="Browse…", command=pick_root, width=12)
    btn_root.pack(side="left")
    info_root = ttk.Label(row_root, text="ⓘ", style="Muted.TLabel", cursor="question_arrow")
    info_root.pack(side="left", padx=(6, 0))
    ToolTip(info_root, "Selectează certificatul Root CA. (Ex. ro_cei_mai_root-ca.cer)")

    # Sub row
    row_sub = ttk.Frame(files)
    row_sub.pack(fill="x", pady=6)
    ttk.Label(row_sub, text="Sub CA", width=10).pack(side="left")
    ent_sub = ttk.Entry(row_sub, textvariable=sub_override_var)
    ent_sub.pack(side="left", fill="x", expand=True, padx=2)
    fp_sub_icon = ttk.Label(row_sub, text="🔒", style="Muted.TLabel", cursor="question_arrow")
    fp_sub_icon.pack(side="left", padx=(0, 2))
    sub_fp_tooltip = ToolTip(fp_sub_icon, "Sub  SHA256: UNKNOWN")
    btn_sub = ttk.Button(row_sub, text="Browse…", command=pick_sub, width=12)
    btn_sub.pack(side="left")
    info_sub = ttk.Label(row_sub, text="ⓘ", style="Muted.TLabel", cursor="question_arrow")
    info_sub.pack(side="left", padx=(6, 0))
    ToolTip(info_sub, "Selectează certificatul Sub/Intermediate CA. (Ex. ro_cei_mai_sub-ca.cer)")

    def copy_fingerprints():
        root_path, sub_path = resolve_cert_paths()
        root_fp = _cert_fp_text(root_path)
        sub_fp = _cert_fp_text(sub_path)
        text = f"Root SHA256: {root_fp}\nSub  SHA256: {sub_fp}"
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    root_fp_label = ttk.Label(files, text="Root SHA256: UNKNOWN", style="Muted.TLabel")
    sub_fp_label = ttk.Label(files, text="Sub  SHA256: UNKNOWN", style="Muted.TLabel")
    fp_actions = ttk.Frame(files)
    fp_actions.pack(anchor="w", padx=(10, 0), pady=(0, 6))
    btn_copy_fps = ttk.Button(fp_actions, text="Copiază amprentele", command=copy_fingerprints, width=18)
    btn_copy_fps.pack(side="left")
    btn_open_bundle = ttk.Button(
        fp_actions,
        text="Deschide locație certificate",
        command=lambda: open_url(str(resource_path("assets/certs"))),
        width=24,
    )
    btn_open_bundle.pack(side="left", padx=(8, 0))
    refresh_cert_source()

    # Hardening options
    opts = ttk.LabelFrame(left_inner, text="Hardening", padding=10)
    opts.pack(fill="x", pady=(0, 10))

    def update_revocation_state():
        if strict_eci_var.get():
            allow_cb.configure(state="disabled")
            strict_cb.configure(state="disabled")
            hard_cb.configure(state="disabled")
            revocation_combo.configure(state="disabled")
        else:
            allow_cb.configure(state="normal")
            strict_cb.configure(state="normal")
            hard_cb.configure(state="normal")
            if not allow_fetch_var.get():
                revocation_mode_var.set("soft-fail")
            revocation_combo.configure(state="readonly" if allow_fetch_var.get() else "disabled")

    def apply_strict_eci():
        if strict_eci_var.get():
            allow_fetch_var.set(True)
            strict_issuer_var.set(True)
            revocation_mode_var.set("require")
        update_revocation_state()

    strict_eci_cb = ttk.Checkbutton(
        opts,
        text="Strict eCI (pin MAI + revocare obligatorie + emitent strict)",
        variable=strict_eci_var,
        command=apply_strict_eci,
    )
    strict_eci_cb.pack(anchor="w", pady=3)

    allow_cb = ttk.Checkbutton(
        opts,
        text="Permite acces la rețea (CRL/AIA) pentru revocare",
        variable=allow_fetch_var,
        command=update_revocation_state,
    )
    allow_cb.pack(anchor="w", pady=3)

    rev_row = ttk.Frame(opts)
    rev_row.pack(anchor="w", pady=(2, 6), fill="x")
    ttk.Label(rev_row, text="Mod revocare", width=14).pack(side="left")
    revocation_combo = ttk.Combobox(
        rev_row,
        textvariable=revocation_mode_var,
        values=["soft-fail", "hard-fail", "require"],
        state="readonly",
        width=14,
    )
    revocation_combo.pack(side="left")
    ttk.Label(
        rev_row,
        text="(aplicat când rețeaua este activă)",
        style="Muted.TLabel",
    ).pack(side="left", padx=(8, 0))

    local_crl_row = ttk.Frame(opts)
    local_crl_row.pack(anchor="w", pady=(0, 6), fill="x")
    local_crl_cb = ttk.Checkbutton(
        local_crl_row,
        text="Folosește CRL locale (assets/certs/*.crl)",
        variable=local_crl_var,
    )
    local_crl_cb.pack(side="left")
    local_crl_count = len(load_local_crls())
    ttk.Label(
        local_crl_row,
        text=f"CRL locale găsite: {local_crl_count}",
        style="Muted.TLabel",
    ).pack(side="left", padx=(8, 0))

    timestamp_cb = ttk.Checkbutton(
        opts,
        text="Verifică timestamp/LTV (dacă există)",
        variable=timestamp_check_var,
    )
    timestamp_cb.pack(anchor="w", pady=3)

    strict_cb = ttk.Checkbutton(
        opts,
        text="Emitent strict (pin Sub CA – verificare criptografică)",
        variable=strict_issuer_var,
    )
    strict_cb.pack(anchor="w", pady=3)

    hard_cb = ttk.Checkbutton(
        opts,
        text="Hard mode: respinge certificate embedded suplimentare",
        variable=hard_mode_var,
    )
    hard_cb.pack(anchor="w", pady=3)

    ToolTip(hard_cb, "Fail-closed. Respinge orice CMS cu certificate suplimentare.")
    update_revocation_state()

    # Actions
    actions = ttk.Frame(left_inner)
    actions.pack(fill="x", pady=(0, 10))

    btn_validate = ttk.Button(actions, text="Validează", width=16)
    btn_validate.pack(side="left")

    btn_export = ttk.Button(actions, text="Salvează raport", width=16, state="disabled")
    btn_export.pack(side="left", padx=(8, 0))

    # Result tabs
    notebook = ttk.Notebook(right_col)
    notebook.pack(fill="both", expand=True)

    tab_res = ttk.Frame(notebook)
    notebook.add(tab_res, text="Rezultat")

    tab_multi = ttk.Frame(notebook)
    notebook.add(tab_multi, text="Semnături multiple")

    inner = ttk.Notebook(tab_res)
    inner.pack(fill="both", expand=True)

    tab_human = ttk.Frame(inner)
    tab_json = ttk.Frame(inner)
    inner.add(tab_human, text="Rezumat (uman)")
    inner.add(tab_json, text="JSON (raw)")

    txt_human = ScrolledText(tab_human, wrap="word")
    txt_human.pack(fill="both", expand=True, padx=6, pady=6)
    txt_human.configure(state="disabled", font=("Consolas", 11))

    txt_json = ScrolledText(tab_json, wrap="word")
    txt_json.pack(fill="both", expand=True, padx=6, pady=6)
    txt_json.configure(state="disabled", font=("Consolas", 10))

    # Signer cert tab
    tab_cert = ttk.Frame(inner)
    inner.add(tab_cert, text="Certificat")
    cert_actions = ttk.Frame(tab_cert)
    cert_actions.pack(fill="x", padx=6, pady=(6, 0))
    btn_copy_cert = ttk.Button(cert_actions, text="Copiază detalii certificat", width=24)
    btn_copy_cert.pack(side="left")
    btn_export_cert = ttk.Button(cert_actions, text="Exportă certificat (.cer)", width=24)
    btn_export_cert.pack(side="left", padx=(8, 0))
    txt_cert = ScrolledText(tab_cert, wrap="word")
    txt_cert.pack(fill="both", expand=True, padx=6, pady=6)
    txt_cert.configure(state="disabled", font=("Consolas", 10))

    # Log tab (network/validator)
    tab_log = ttk.Frame(inner)
    inner.add(tab_log, text="Log")
    txt_log = ScrolledText(tab_log, wrap="word")
    txt_log.pack(fill="both", expand=True, padx=6, pady=6)
    txt_log.configure(state="disabled", font=("Consolas", 10))

    # Multi-signature view
    multi_header = ttk.Frame(tab_multi)
    multi_header.pack(fill="x", padx=6, pady=(6, 0))
    multi_status = ttk.Label(multi_header, text="—")
    multi_status.pack(side="left")
    multi_note = ttk.Label(
        multi_header,
        text="Fiecare semnătură este așteptată să provină din eCI.",
        style="Muted.TLabel",
    )
    multi_note.pack(side="left", padx=(12, 0))

    multi_actions = ttk.Frame(tab_multi)
    multi_actions.pack(fill="x", padx=6, pady=(6, 0))
    btn_export_all = ttk.Button(multi_actions, text="Salvează toate rapoartele", width=26)
    btn_export_all.pack(side="left")

    multi_summary = ScrolledText(tab_multi, wrap="word", height=5)
    multi_summary.pack(fill="x", expand=False, padx=6, pady=(6, 0))
    multi_summary.configure(state="disabled", font=("Consolas", 10))

    multi_inner = ttk.Notebook(tab_multi)
    multi_inner.pack(fill="both", expand=True, padx=6, pady=6)

    log_lines: List[str] = []

    class _LogCapture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            msg = self.format(record)
            log_lines.append(msg)

    log_handler = _LogCapture()
    log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    for name in ("pyhanko", "pyhanko_certvalidator"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(log_handler)

    def refresh_log_view():
        txt_log.configure(state="normal")
        txt_log.delete("1.0", "end")
        if log_lines:
            txt_log.insert("1.0", "\n".join(log_lines))
        txt_log.configure(state="disabled")

    def signer_validity_status(res: Result) -> str:
        try:
            if not res.signer_not_before or not res.signer_not_after:
                return "UNKNOWN"
            nb = datetime.fromisoformat(res.signer_not_before)
            na = datetime.fromisoformat(res.signer_not_after)
            now = datetime.now(tz=nb.tzinfo) if nb.tzinfo else datetime.now()
            if now < nb:
                return "NEVALID (prea devreme)"
            if now > na:
                return "EXPIRAT"
            return "VALID"
        except Exception:
            return "UNKNOWN"

    def copy_signer_details():
        if last_result is None:
            return
        status = signer_validity_status(last_result)
        lines = [
            f"Subject: {last_result.signer_subject or 'UNKNOWN'}",
            f"Emitent: {last_result.signer_issuer or 'UNKNOWN'}",
            f"SHA256: {last_result.signer_cert_sha256 or 'UNKNOWN'}",
            f"Not Before: {last_result.signer_not_before or 'UNKNOWN'}",
            f"Not After: {last_result.signer_not_after or 'UNKNOWN'}",
            f"Stare: {status}",
            f"Key Usage: {last_result.signer_key_usage or 'UNKNOWN'}",
            f"EKU OIDs: {', '.join(last_result.signer_eku_oids) if last_result.signer_eku_oids else 'UNKNOWN'}",
            f"Policy OIDs: {', '.join(last_result.signer_policy_oids) if last_result.signer_policy_oids else 'UNKNOWN'}",
        ]
        if last_result.timestamp_value or last_result.content_timestamp_value:
            lines.append(f"Timestamp: {last_result.timestamp_value or 'UNKNOWN'}")
            lines.append(f"TSA: {last_result.timestamp_tsa_subject or 'UNKNOWN'}")
            if last_result.content_timestamp_value:
                lines.append(f"Content TS: {last_result.content_timestamp_value}")
                lines.append(f"Content TSA: {last_result.content_timestamp_tsa_subject or 'UNKNOWN'}")
        root.clipboard_clear()
        root.clipboard_append("\n".join(lines))
        root.update()

    def export_signer_cert():
        pdf = pdf_var.get().strip()
        if not pdf:
            messagebox.showerror("Eroare", "Alege un PDF.")
            return
        pdf_path = Path(pdf)
        if not pdf_path.exists():
            messagebox.showerror("Eroare", "PDF inexistent.")
            return
        default_name = pdf_path.with_suffix(".signer.cer").name
        dest = filedialog.asksaveasfilename(
            title="Salvează certificatul semnatarului",
            defaultextension=".cer",
            initialfile=default_name,
            filetypes=[("Certificate", "*.cer"), ("All files", "*.*")],
        )
        if not dest:
            return
        ok = _save_signer_cert_bytes(pdf_path, Path(dest))
        if ok:
            messagebox.showinfo("Export reușit", f"Certificat salvat:\n{dest}")
        else:
            messagebox.showerror("Eroare", "Nu am putut extrage certificatul semnatarului.")

    def mark_log_tab(unread: bool):
        inner.tab(tab_log, text="Log *" if unread and log_lines else "Log")

    def on_tab_changed(_event=None):
        current = inner.select()
        if current == str(tab_log):
            mark_log_tab(False)

    inner.bind("<<NotebookTabChanged>>", on_tab_changed)

    last_result: Optional[Result] = None

    def set_single_actions_enabled(enabled: bool):
        state = "normal" if enabled else "disabled"
        btn_export.configure(state=state)
        btn_copy_cert.configure(state=state)
        btn_export_cert.configure(state=state)

    def set_mode_single():
        notebook.tab(tab_res, state="normal")
        notebook.tab(tab_multi, state="disabled")
        notebook.select(tab_res)

    def set_mode_multi():
        notebook.tab(tab_res, state="disabled")
        notebook.tab(tab_multi, state="normal")
        notebook.select(tab_multi)

    def build_cert_lines(res: Result) -> List[str]:
        lines = [
            f"Subject: {res.signer_subject or 'UNKNOWN'}",
            f"Emitent: {res.signer_issuer or 'UNKNOWN'}",
            f"SHA256: {res.signer_cert_sha256 or 'UNKNOWN'}",
            f"Not Before: {res.signer_not_before or 'UNKNOWN'}",
            f"Not After: {res.signer_not_after or 'UNKNOWN'}",
            f"Stare: {signer_validity_status(res)}",
            f"Key Usage: {res.signer_key_usage or 'UNKNOWN'}",
            f"EKU OIDs: {', '.join(res.signer_eku_oids) if res.signer_eku_oids else 'UNKNOWN'}",
            f"Policy OIDs: {', '.join(res.signer_policy_oids) if res.signer_policy_oids else 'UNKNOWN'}",
        ]
        if res.timestamp_value or res.content_timestamp_value:
            lines.append("")
            lines.append(f"Timestamp: {res.timestamp_value or 'UNKNOWN'}")
            lines.append(f"TSA: {res.timestamp_tsa_subject or 'UNKNOWN'}")
            if res.content_timestamp_value:
                lines.append(f"Content TS: {res.content_timestamp_value}")
                lines.append(f"Content TSA: {res.content_timestamp_tsa_subject or 'UNKNOWN'}")
        return lines

    def clear_multi_tabs():
        for tab_id in multi_inner.tabs():
            multi_inner.forget(tab_id)

    def show_result(res: Result):
        nonlocal last_result
        last_result = res
        set_mode_single()
        set_single_actions_enabled(True)

        txt_human.configure(state="normal")
        txt_human.delete("1.0", "end")
        txt_human.insert("1.0", result_to_human(res))
        txt_human.configure(state="disabled")

        txt_json.configure(state="normal")
        txt_json.delete("1.0", "end")
        txt_json.insert("1.0", result_to_json(res))
        txt_json.configure(state="disabled")

        cert_lines = build_cert_lines(res)
        txt_cert.configure(state="normal")
        txt_cert.delete("1.0", "end")
        txt_cert.insert("1.0", "\n".join(cert_lines))
        txt_cert.configure(state="disabled")

        log_lines.append("Detalii certificat semnatar:")
        log_lines.extend(cert_lines)

        refresh_log_view()
        mark_log_tab(True)

        update_status(res.ok, "VALID" if res.ok else "INVALID")

    def show_multi_results(items: List[Tuple[Result, Any]], pdf_path: Path):
        nonlocal last_result
        last_result = None
        set_mode_multi()
        set_single_actions_enabled(False)
        clear_multi_tabs()

        results = [r for r, _ in items]
        status_parts = ["VALID" if r.ok else "INVALID" for r in results]
        status_text = " - ".join(status_parts) if status_parts else "FĂRĂ SEMNĂTURI"
        all_ok = all(r.ok for r in results) if results else False
        any_ok = any(r.ok for r in results) if results else False
        if all_ok:
            overall_style = "StatusGood.TLabel"
            update_status(True, status_text)
        elif any_ok:
            overall_style = "StatusWarn.TLabel"
            update_status(None, status_text)
        else:
            overall_style = "StatusBad.TLabel"
            update_status(False, status_text)
        multi_status.configure(text=status_text, style=overall_style)

        summary_lines: List[str] = []
        for idx, res in enumerate(results, start=1):
            subject = res.signer_subject or "UNKNOWN"
            issuer = res.signer_issuer or "UNKNOWN"
            policy = ", ".join(res.signer_policy_oids) if res.signer_policy_oids else "UNKNOWN"
            ts_note = res.timestamp_value or res.content_timestamp_value or "—"
            summary_lines.append(
                f"Semnătura {idx}: {'VALID' if res.ok else 'INVALID'} | "
                f"Subiect: {subject} | Emitent: {issuer} | Policy OID: {policy} | Timestamp: {ts_note}"
            )
        multi_summary.configure(state="normal")
        multi_summary.delete("1.0", "end")
        if summary_lines:
            multi_summary.insert("1.0", "\n".join(summary_lines))
        multi_summary.configure(state="disabled")

        def export_report_for_result(res: Result):
            txt, js = export_report(pdf_path, res)
            messagebox.showinfo(
                "Export finalizat",
                f"Raport salvat:\n\n{txt.name}\n{js.name}",
            )

        def export_all_reports():
            for r in results:
                export_report(pdf_path, r)
            messagebox.showinfo(
                "Export finalizat",
                f"Au fost salvate {len(results)} rapoarte.",
            )

        def export_cert_for_sig(embedded_sig: Any, idx: int):
            default_name = f"{pdf_path.stem}.sig{idx}.cer"
            dest = filedialog.asksaveasfilename(
                title="Salvează certificatul semnatarului",
                defaultextension=".cer",
                initialfile=default_name,
                filetypes=[("Certificate", "*.cer"), ("All files", "*.*")],
            )
            if not dest:
                return
            ok = _save_signer_cert_bytes_from_embedded(embedded_sig, Path(dest))
            if ok:
                messagebox.showinfo("Export reușit", f"Certificat salvat:\n{dest}")
            else:
                messagebox.showerror("Eroare", "Nu am putut extrage certificatul semnatarului.")

        def copy_cert_for_result(res: Result):
            lines = build_cert_lines(res)
            root.clipboard_clear()
            root.clipboard_append("\n".join(lines))
            root.update()

        btn_export_all.configure(command=export_all_reports)

        for idx, (res, embedded_sig) in enumerate(items, start=1):
            sig_tab = ttk.Frame(multi_inner)
            multi_inner.add(sig_tab, text=f"Semnătura {idx}")

            sig_actions = ttk.Frame(sig_tab)
            sig_actions.pack(fill="x", padx=6, pady=(6, 0))
            ttk.Button(
                sig_actions,
                text="Salvează raport",
                width=18,
                command=lambda r=res: export_report_for_result(r),
            ).pack(side="left")
            ttk.Button(
                sig_actions,
                text="Copiază detalii certificat",
                width=24,
                command=lambda r=res: copy_cert_for_result(r),
            ).pack(side="left", padx=(8, 0))
            ttk.Button(
                sig_actions,
                text="Exportă certificat (.cer)",
                width=22,
                command=lambda s=embedded_sig, i=idx: export_cert_for_sig(s, i),
            ).pack(side="left", padx=(8, 0))

            sig_inner = ttk.Notebook(sig_tab)
            sig_inner.pack(fill="both", expand=True)

            sig_human = ttk.Frame(sig_inner)
            sig_json = ttk.Frame(sig_inner)
            sig_cert = ttk.Frame(sig_inner)
            sig_log = ttk.Frame(sig_inner)
            sig_inner.add(sig_human, text="Rezumat (uman)")
            sig_inner.add(sig_json, text="JSON (raw)")
            sig_inner.add(sig_cert, text="Certificat")
            sig_inner.add(sig_log, text="Log")

            txt_sig_human = ScrolledText(sig_human, wrap="word")
            txt_sig_human.pack(fill="both", expand=True, padx=6, pady=6)
            txt_sig_human.insert("1.0", result_to_human(res))
            txt_sig_human.configure(state="disabled", font=("Consolas", 11))

            txt_sig_json = ScrolledText(sig_json, wrap="word")
            txt_sig_json.pack(fill="both", expand=True, padx=6, pady=6)
            txt_sig_json.insert("1.0", result_to_json(res))
            txt_sig_json.configure(state="disabled", font=("Consolas", 10))

            txt_sig_cert = ScrolledText(sig_cert, wrap="word")
            txt_sig_cert.pack(fill="both", expand=True, padx=6, pady=6)
            txt_sig_cert.insert("1.0", "\n".join(build_cert_lines(res)))
            txt_sig_cert.configure(state="disabled", font=("Consolas", 10))

            txt_sig_log = ScrolledText(sig_log, wrap="word")
            txt_sig_log.pack(fill="both", expand=True, padx=6, pady=6)
            if log_lines:
                txt_sig_log.insert("1.0", "\n".join(log_lines))
            txt_sig_log.configure(state="disabled", font=("Consolas", 10))
    def do_validate():
        pdf = pdf_var.get().strip()
        if not pdf:
            messagebox.showerror("Eroare", "Alege un PDF.")
            return

        log_lines.clear()
        refresh_log_view()
        mark_log_tab(False)

        pdf_path = Path(pdf)
        root_path, sub_path = resolve_cert_paths()

        if root_path is None or sub_path is None:
            messagebox.showerror("Eroare", "Root CA sau Sub CA lipsă.")
            return

        update_status(None, "Validare în curs…")

        allow_fetching = allow_fetch_var.get()
        revocation_mode = revocation_mode_var.get().strip() or "soft-fail"
        strict_issuer = strict_issuer_var.get()
        hard_mode = hard_mode_var.get()
        strict_eci = strict_eci_var.get()
        local_crls = load_local_crls() if local_crl_var.get() else None
        require_timestamp = timestamp_check_var.get()

        if strict_eci:
            allow_fetching = True
            revocation_mode = "require"
            strict_issuer = True
        if not allow_fetching and not local_crls:
            revocation_mode = "soft-fail"

        try:
            with pdf_path.open("rb") as f:
                r = PdfFileReader(f)
                sigs = r.embedded_signatures or []
                sig_count = len(sigs)

                if sig_count > 1:
                    root_cert = _load_cert_any(root_path)
                    sub_cert = _load_cert_any(sub_path)
                    root_fp = _cert_sha256_der(root_cert)
                    sub_fp = _cert_sha256_der(sub_cert)

                    if strict_eci:
                        if root_fp not in MAI_ROOT_SHA256:
                            base = Result(
                                ok=False,
                                message="STRICT_ECI_ROOT_NOT_MAI",
                                signature_count=sig_count,
                                root_cert_sha256=root_fp,
                                sub_cert_sha256=sub_fp,
                                strict_issuer_enabled=strict_issuer,
                                hard_mode_enabled=hard_mode,
                                allow_fetching_enabled=allow_fetching,
                                revocation_mode=revocation_mode,
                                local_crl_enabled=bool(local_crls),
                                local_crl_count=len(local_crls or []),
                                timestamp_check_enabled=bool(require_timestamp),
                                timestamp_ok=None,
                                timestamp_info=None,
                                strict_eci_enabled=True,
                                strict_eci_ok=False,
                                strict_eci_notes=["Root CA nu corespunde amprentei MAI."],
                                used_root_path=str(root_path),
                                used_sub_path=str(sub_path),
                            )
                            show_multi_results(
                                [(Result(**base.__dict__), sig) for sig in sigs],
                                pdf_path,
                            )
                            return
                        if sub_fp not in MAI_SUB_SHA256:
                            base = Result(
                                ok=False,
                                message="STRICT_ECI_SUB_NOT_MAI",
                                signature_count=sig_count,
                                root_cert_sha256=root_fp,
                                sub_cert_sha256=sub_fp,
                                strict_issuer_enabled=strict_issuer,
                                hard_mode_enabled=hard_mode,
                                allow_fetching_enabled=allow_fetching,
                                revocation_mode=revocation_mode,
                                local_crl_enabled=bool(local_crls),
                                local_crl_count=len(local_crls or []),
                                timestamp_check_enabled=bool(require_timestamp),
                                timestamp_ok=None,
                                timestamp_info=None,
                                strict_eci_enabled=True,
                                strict_eci_ok=False,
                                strict_eci_notes=["Sub CA nu corespunde amprentei MAI."],
                                used_root_path=str(root_path),
                                used_sub_path=str(sub_path),
                            )
                            show_multi_results(
                                [(Result(**base.__dict__), sig) for sig in sigs],
                                pdf_path,
                            )
                            return

                    items: List[Tuple[Result, Any]] = []
                    for idx, embedded_sig in enumerate(sigs, start=1):
                        log_lines.append(f"=== Semnătura {idx} ===")
                        res = validate_embedded_signature_against_two_cas(
                                embedded_sig=embedded_sig,
                                signature_count=sig_count,
                                root_cert=root_cert,
                                sub_cert=sub_cert,
                                root_fp=root_fp,
                                sub_fp=sub_fp,
                                allow_fetching=allow_fetching,
                                revocation_mode=revocation_mode,
                                strict_issuer=strict_issuer,
                                hard_mode=hard_mode,
                                strict_eci=strict_eci,
                                local_crls=local_crls,
                                require_timestamp=require_timestamp,
                                root_ca_path=root_path,
                                sub_ca_path=sub_path,
                            )
                        items.append((res, embedded_sig))

                    show_multi_results(items, pdf_path)
                    return
        except Exception as e:
            res = Result(
                ok=False,
                message=f"EXCEPTION: {type(e).__name__}: {e}",
                signature_count=0,
                strict_issuer_enabled=bool(strict_issuer),
                hard_mode_enabled=bool(hard_mode),
                allow_fetching_enabled=bool(allow_fetching),
                revocation_mode=str(revocation_mode),
                local_crl_enabled=bool(local_crls),
                local_crl_count=len(local_crls or []),
                timestamp_check_enabled=bool(require_timestamp),
                strict_eci_enabled=bool(strict_eci),
                used_root_path=str(root_path),
                used_sub_path=str(sub_path),
            )
            show_result(res)
            return

        res = validate_pdf_against_two_cas(
            pdf_path=pdf_path,
            root_ca_path=root_path,
            sub_ca_path=sub_path,
            allow_fetching=allow_fetching,
            revocation_mode=revocation_mode,
            strict_issuer=strict_issuer,
            hard_mode=hard_mode,
            strict_eci=strict_eci,
            local_crls=local_crls,
            require_timestamp=require_timestamp,
        )

        show_result(res)

    def do_export():
        if last_result is None:
            return
        pdf_path = Path(pdf_var.get())
        txt, js = export_report(pdf_path, last_result)
        messagebox.showinfo(
            "Export finalizat",
            f"Raport salvat:\n\n{txt.name}\n{js.name}",
        )

    btn_validate.configure(command=do_validate)
    btn_export.configure(command=do_export)
    btn_copy_cert.configure(command=lambda: copy_signer_details())
    btn_export_cert.configure(command=lambda: export_signer_cert())
    set_mode_single()
    set_single_actions_enabled(False)

    # Size window to fit left column content by default
    try:
        root.update_idletasks()
        left_h = left_inner.winfo_reqheight()
        header_h = header.winfo_reqheight()
        desired_h = header_h + left_h + 48  # padding + spacing
        min_w, min_h = 920, 660
        desired_h = max(desired_h, min_h)
        root.geometry(f"1020x{desired_h}")
    except Exception:
        pass

    root.deiconify()

    root.mainloop()
    return 0


# =============================================================================
# Entrypoint
# =============================================================================
def main():
    cli_markers = {
        "--cli",
        "--pdf",
        "--root",
        "--sub",
        "--use-bundled",
        "--json",
        "--allow-fetching",
        "--revocation-mode",
        "--strict-issuer",
        "--hard-mode",
        "--strict-eci",
        "--local-crl",
        "--timestamp",
        "-h",
        "--help",
    }
    if any(flag in sys.argv[1:] for flag in cli_markers):
        return run_cli(sys.argv[1:])
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())


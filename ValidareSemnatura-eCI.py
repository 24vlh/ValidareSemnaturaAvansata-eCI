#!/usr/bin/env python3

from __future__ import annotations
from PIL import Image, ImageTk

import argparse
import json
import sys
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any, Dict

# GUI is optional (stdlib)
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception:
    tk = None
    filedialog = None
    messagebox = None

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509 as asn1_x509


# ----------------------------
# Core helpers
# ----------------------------
def resource_path(rel):
    import sys
    from pathlib import Path
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / rel
    return Path(__file__).resolve().parent / rel

@dataclass
class Result:
    ok: bool
    message: str
    signature_intact: bool = False
    signature_valid: bool = False
    signature_trusted: bool = False
    signature_count: int = 0

    signer_subject: Optional[str] = None
    signer_issuer: Optional[str] = None
    signer_cert_sha256: Optional[str] = None

    root_cert_sha256: Optional[str] = None
    sub_cert_sha256: Optional[str] = None

    # Policy flags / checks
    strict_issuer_enabled: bool = False
    strict_issuer_expected: Optional[str] = None
    strict_issuer_actual: Optional[str] = None

    details: Optional[Dict[str, Any]] = None


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


def validate_pdf_against_two_cas(
    pdf_path: Path,
    root_ca_path: Path,
    sub_ca_path: Path,
    allow_fetching: bool = False,
    strict_issuer: bool = False,
) -> Result:
    if not pdf_path.exists():
        return Result(ok=False, message=f"NO_SUCH_PDF: {pdf_path}")

    if not root_ca_path.exists():
        return Result(ok=False, message=f"NO_SUCH_ROOT_CA: {root_ca_path}")

    if not sub_ca_path.exists():
        return Result(ok=False, message=f"NO_SUCH_SUB_CA: {sub_ca_path}")

    # Load provided CA certs (PEM or DER)
    root_cert = _load_cert_any(root_ca_path)
    sub_cert = _load_cert_any(sub_ca_path)

    root_fp = _cert_sha256_der(root_cert)
    sub_fp = _cert_sha256_der(sub_cert)

    vc = ValidationContext(
        trust_roots=[_to_asn1(root_cert)],
        other_certs=[_to_asn1(sub_cert)],
        allow_fetching=allow_fetching,
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
                )

            # Hard rule: exactly one signature
            if sig_count != 1:
                return Result(
                    ok=False,
                    message="PDF_MUST_HAVE_EXACTLY_ONE_SIGNATURE",
                    signature_count=sig_count,
                    root_cert_sha256=root_fp,
                    sub_cert_sha256=sub_fp,
                    strict_issuer_enabled=strict_issuer,
                )

            status = validate_pdf_signature(sigs[0], vc)

            intact = bool(getattr(status, "intact", False))
            valid = bool(getattr(status, "valid", False))
            trusted = bool(getattr(status, "trusted", False))

            # Extract signer cert (asn1crypto) + convert to cryptography for stable DN formatting
            signer_asn1 = None
            signer_crypto = None
            try:
                signer_asn1 = status.signing_cert
            except Exception:
                signer_asn1 = None

            signer_subject = None
            signer_issuer = None
            signer_fp = None
            if signer_asn1 is not None:
                try:
                    signer_subject = signer_asn1.subject.human_friendly
                    signer_issuer = signer_asn1.issuer.human_friendly
                    signer_fp = hashlib.sha256(signer_asn1.dump()).hexdigest()
                    signer_crypto = x509.load_der_x509_certificate(signer_asn1.dump())
                except Exception:
                    pass

            # Optional hardening: issuer DN must equal the provided Sub CA subject DN
            expected_issuer = None
            actual_issuer = None
            if strict_issuer:
                expected_issuer = sub_cert.subject.rfc4514_string()
                if signer_crypto is None:
                    return Result(
                        ok=False,
                        message="STRICT_ISSUER_NO_SIGNER_CERT_EXTRACTED",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=True,
                        strict_issuer_expected=expected_issuer,
                        strict_issuer_actual=None,
                        details={"reason": "Could not extract/parse signing cert from PDF signature."},
                    )

                actual_issuer = signer_crypto.issuer.rfc4514_string()
                if actual_issuer != expected_issuer:
                    return Result(
                        ok=False,
                        message="STRICT_ISSUER_MISMATCH",
                        signature_intact=intact,
                        signature_valid=valid,
                        signature_trusted=trusted,
                        signature_count=1,
                        signer_subject=signer_subject,
                        signer_issuer=signer_issuer,
                        signer_cert_sha256=signer_fp,
                        root_cert_sha256=root_fp,
                        sub_cert_sha256=sub_fp,
                        strict_issuer_enabled=True,
                        strict_issuer_expected=expected_issuer,
                        strict_issuer_actual=actual_issuer,
                        details={
                            "expected_issuer_rfc4514": expected_issuer,
                            "actual_issuer_rfc4514": actual_issuer,
                        },
                    )

            ok = intact and valid and trusted

            summary = {
                "intact": intact,
                "valid": valid,
                "trusted": trusted,
                "modification_level": str(getattr(status, "modification_level", "")),
                "coverage": str(getattr(status, "coverage", "")),
                "allow_fetching": bool(allow_fetching),
                "strict_issuer_enabled": bool(strict_issuer),
            }

            return Result(
                ok=ok,
                message="OK" if ok else "SIGNATURE_OR_CHAIN_VALIDATION_FAILED",
                signature_intact=intact,
                signature_valid=valid,
                signature_trusted=trusted,
                signature_count=1,
                signer_subject=signer_subject,
                signer_issuer=signer_issuer,
                signer_cert_sha256=signer_fp,
                root_cert_sha256=root_fp,
                sub_cert_sha256=sub_fp,
                strict_issuer_enabled=bool(strict_issuer),
                strict_issuer_expected=expected_issuer,
                strict_issuer_actual=actual_issuer,
                details=summary,
            )

    except Exception as e:
        return Result(
            ok=False,
            message=f"EXCEPTION: {type(e).__name__}: {e}",
            signature_count=0,
            root_cert_sha256=root_fp,
            sub_cert_sha256=sub_fp,
            strict_issuer_enabled=bool(strict_issuer),
        )


def result_to_json(res: Result) -> str:
    return json.dumps(res.__dict__, ensure_ascii=False, indent=2)


# ----------------------------
# GUI
# ----------------------------

def run_gui(default_root: Optional[Path], default_sub: Optional[Path]) -> int:
    if tk is None:
        print("GUI unavailable (tkinter not present). Use CLI mode.", file=sys.stderr)
        return 3

    root = tk.Tk()
    root.iconbitmap(resource_path("assets/app.ico"))
    root.title("Validare Semnătură Digitală")

    pdf_var = tk.StringVar(value="")
    root_var = tk.StringVar(value=str(default_root) if default_root else "")
    sub_var = tk.StringVar(value=str(default_sub) if default_sub else "")
    allow_fetch_var = tk.BooleanVar(value=False)
    strict_issuer_var = tk.BooleanVar(value=False)

    def pick_pdf():
        p = filedialog.askopenfilename(
            title="Selectează document PDF semnat",
            filetypes=[("Documente PDF", "*.pdf"), ("Toate", "*.*")],
        )
        if p:
            pdf_var.set(p)

    def pick_root():
        p = filedialog.askopenfilename(
            title="Selectează Certificatul Root CA (.cer/.crt/.pem)",
            filetypes=[("Documente Cert", "*.cer *.crt *.pem"), ("Toate", "*.*")],
        )
        if p:
            root_var.set(p)

    def pick_sub():
        p = filedialog.askopenfilename(
            title="Selectează Certificatul Sub/Intermediate CA (.cer/.crt/.pem)",
            filetypes=[("Documente Cert", "*.cer *.crt *.pem"), ("Toate", "*.*")],
        )
        if p:
            sub_var.set(p)

    def do_validate():
        pdf_path = Path(pdf_var.get()).expanduser()
        root_path = Path(root_var.get()).expanduser()
        sub_path = Path(sub_var.get()).expanduser()

        res = validate_pdf_against_two_cas(
            pdf_path=pdf_path,
            root_ca_path=root_path,
            sub_ca_path=sub_path,
            allow_fetching=allow_fetch_var.get(),
            strict_issuer=strict_issuer_var.get(),
        )

        if res.ok:
            messagebox.showinfo("VALID ✅", f"VALID\n\n{result_to_json(res)}")
        else:
            messagebox.showerror("INVALID ❌", f"INVALID\n\n{result_to_json(res)}")

    frm = tk.Frame(root, padx=12, pady=12)
    frm.pack(fill="both", expand=True)
    logo_img = Image.open(resource_path("assets/logo.png")).convert("RGBA")
    logo_img = logo_img.resize((120, 120))
    logo = ImageTk.PhotoImage(logo_img)

    logo_label = tk.Label(frm, image=logo)
    logo_label.image = logo  # keep reference
    logo_label.pack(pady=(0, 10))

    def row(label, var, pick_cmd):
        r = tk.Frame(frm)
        r.pack(fill="x", pady=4)
        tk.Label(r, text=label, width=14, anchor="w").pack(side="left")
        tk.Entry(r, textvariable=var).pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(r, text="Browse…", command=pick_cmd).pack(side="left")

    row("PDF", pdf_var, pick_pdf)
    row("Root CA", root_var, pick_root)
    row("Sub CA", sub_var, pick_sub)

    opts = tk.Frame(frm)
    opts.pack(fill="x", pady=8)

    tk.Checkbutton(
        opts,
        text="Permite extragere revocation/AIA (network)",
        variable=allow_fetch_var,
    ).pack(anchor="w")

    tk.Checkbutton(
        opts,
        text="Validare a autorității cu strictețe (Semnatarul trebuie să fie emis de Sub CA-ul furnizat)",
        variable=strict_issuer_var,
    ).pack(anchor="w")

    tk.Button(frm, text="Validează", command=do_validate, height=2).pack(fill="x", pady=8)

    tk.Label(
        frm,
        text="Regulă: PDF-ul trebuie să conțină exact o singură semnătură încorporată.",
        fg="gray",
        anchor="w",
    ).pack(fill="x")

    root.mainloop()
    return 0


# ----------------------------
# CLI
# ----------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Validare cu un singur click a semnăturii PDF față de certificatele Root + Sub CA.")
    ap.add_argument("--pdf", type=str, help="Cale către PDF-ul semnat")
    ap.add_argument("--root", type=str, help="Cale către certificatul Root CA (.cer/.pem)")
    ap.add_argument("--sub", type=str, help="Cale către certificatul Sub / CA intermediar (.cer/.pem)")
    ap.add_argument("--allow-fetching", action="store_true", help="Permite accesul la rețea pentru validarea lanțului / revocării.")
    ap.add_argument("--strict-issuer", action="store_true", help="Solicită ca DN-ul emitentului semnatarului să fie identic cu DN-ul Sub CA-ului furnizat.")
    ap.add_argument("--json", action="store_true", help="Afișează doar rezultatul JSON")
    args = ap.parse_args()

    # If no args: start GUI and auto-fill CA paths if present beside script/exe.
    if not args.pdf and not args.root and not args.sub:
        here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
        default_root = next(
            (p for p in [here / "ro_cei_mai_root-ca.cer", here / "ro_cei_mai_root-ca.pem"] if p.exists()),
            None,
        )
        default_sub = next(
            (p for p in [here / "ro_cei_mai_sub-ca.cer", here / "ro_cei_mai_sub-ca.pem"] if p.exists()),
            None,
        )
        return run_gui(default_root, default_sub)

    if not (args.pdf and args.root and args.sub):
        print("Argumente lipsă. Specificați --pdf, --root și --sub sau porniți aplicația fără argumente pentru modul grafic.", file=sys.stderr)
        return 2

    res = validate_pdf_against_two_cas(
        pdf_path=Path(args.pdf),
        root_ca_path=Path(args.root),
        sub_ca_path=Path(args.sub),
        allow_fetching=bool(args.allow_fetching),
        strict_issuer=bool(args.strict_issuer),
    )

    if args.json:
        print(result_to_json(res))
    else:
        print(("VALID ✅" if res.ok else "INVALID ❌") + "\n" + result_to_json(res))

    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

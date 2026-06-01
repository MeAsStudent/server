#!/usr/bin/env python3
"""
Android Key Attestation verification server.

POST /verify
  Body : { "challenge": "...", "certificates": [{"derHex": "..."}, ...] }
  Reply: {
           "trusted": bool,
           "verdict": str,
           "reason": str,
           "details": [ {"label": "...", "value": "..."}, ... ]  # ordered, for UI
         }

Verdicts:
  DEVICE_TRUSTED     — all checks pass
  APP_TAMPERED       — hardware OK, but APK signing cert doesn't match
  DEVICE_NOT_TRUSTED — hardware / chain / boot checks failed
"""

from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature
import requests
import os

app = Flask(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
TRUSTED_APK_FINGERPRINT = os.environ.get(
    "TRUSTED_APK_FINGERPRINT",
    "B4D8862F2E9625AF8BBC3E7C70FE2222A56573999BE76A121F62CCC0241DA8D9"
).upper()

ATTESTATION_OID       = "1.3.6.1.4.1.11129.2.1.17"
GOOGLE_REVOCATION_URL = "https://android.googleapis.com/attestation/status"


def colonize(hex_str: str) -> str:
    """ABCD... -> AB:CD:..."""
    return ":".join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))

# ── ASN.1 TLV helpers ──────────────────────────────────────────────────────────

def parse_tlv(data: bytes, offset: int = 0):
    """Parse one TLV. Returns (tag_class, constructed, tag_num, value_bytes, next_offset)."""
    b0 = data[offset]; offset += 1
    tag_class   = (b0 >> 6) & 3
    constructed = bool((b0 >> 5) & 1)
    tag_num     = b0 & 0x1F

    if tag_num == 0x1F:                 # long-form tag
        tag_num = 0
        while True:
            b = data[offset]; offset += 1
            tag_num = (tag_num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break

    b = data[offset]; offset += 1
    if b < 0x80:
        ln = b
    else:
        n  = b & 0x7F
        ln = int.from_bytes(data[offset:offset + n], "big"); offset += n

    return tag_class, constructed, tag_num, data[offset:offset + ln], offset + ln


def seq_items(data: bytes) -> list:
    """Parse all TLVs inside a SEQUENCE / SET value."""
    items = []; pos = 0
    while pos < len(data):
        tc, cst, tn, val, pos = parse_tlv(data, pos)
        items.append((tc, cst, tn, val))
    return items


def find_ctx(items: list, tag_num: int):
    """Return value bytes of the first context-specific element matching tag_num, or None."""
    for tc, _, tn, val in items:
        if tc == 2 and tn == tag_num:
            return val
    return None

# ── 1. Certificate chain verification ─────────────────────────────────────────

def verify_chain(certs: list):
    for i in range(len(certs) - 1):
        sub     = certs[i]
        iss_pub = certs[i + 1].public_key()
        try:
            if isinstance(iss_pub, ec.EllipticCurvePublicKey):
                iss_pub.verify(sub.signature, sub.tbs_certificate_bytes,
                               ec.ECDSA(sub.signature_hash_algorithm))
            elif isinstance(iss_pub, rsa.RSAPublicKey):
                iss_pub.verify(sub.signature, sub.tbs_certificate_bytes,
                               padding.PKCS1v15(), sub.signature_hash_algorithm)
            else:
                return False, f"Unsupported key type at cert[{i + 1}]"
        except InvalidSignature:
            return False, f"cert[{i}] is not signed by cert[{i + 1}]"

    root_subj = certs[-1].subject.rfc4514_string()
    if not ("O=Google LLC" in root_subj and "OU=Android" in root_subj):
        return False, f"Root CA is not a Google Android CA: {root_subj}"

    return True, ""

# ── 2. Revocation check ────────────────────────────────────────────────────────

def check_revocation(cert):
    """Returns (revoked: bool, status_string)."""
    serial_hex = format(cert.serial_number, "X").upper()
    try:
        r = requests.get(GOOGLE_REVOCATION_URL, timeout=5)
        if r.status_code == 200:
            entries = r.json().get("entries", {})
            entry   = entries.get(serial_hex) or entries.get(serial_hex.lower())
            if entry:
                return True, f"REVOKED — {entry.get('reason', 'unknown reason')}"
            return False, "VALID (not in revocation list)"
        return False, f"CHECK SKIPPED (Google returned {r.status_code})"
    except Exception:
        return False, "CHECK SKIPPED (could not reach Google)"

# ── 3. Attestation extension parsing ──────────────────────────────────────────

SEC_LEVELS  = {0: "Software", 1: "TEE", 2: "StrongBox"}
BOOT_STATES = {0: "Verified (Green)", 1: "Self-Signed (Yellow)",
               2: "Unverified (Orange)", 3: "Failed (Red)"}


def parse_attestation(cert, expected_challenge: str) -> dict:
    """
    Parse the Android Key Attestation extension.
    Always returns the fields it can read (for display), plus 'ok'/'reason'
    indicating whether the hardware trust checks passed.
    """
    out = {
        "ok": False, "reason": "",
        "security_level": "?", "challenge": "?", "challenge_match": False,
        "boot_state": "?", "bootloader": "?",
        "package_name": None, "package_version": None,
        "fingerprints": [],
    }

    raw = None
    for ext in cert.extensions:
        if ext.oid.dotted_string == ATTESTATION_OID:
            raw = ext.value.value
            break
    if raw is None:
        out["reason"] = "Attestation extension not found in leaf certificate"
        return out

    if raw[0] == 0x04:                  # unwrap outer OCTET STRING if present
        _, _, _, raw, _ = parse_tlv(raw, 0)

    try:
        _, _, _, seq_val, _ = parse_tlv(raw, 0)
        top = seq_items(seq_val)
        if len(top) < 8:
            out["reason"] = f"KeyDescription has {len(top)} elements (expected >= 8)"
            return out

        # [1] attestationSecurityLevel
        att_sec = int.from_bytes(top[1][3], "big") if top[1][3] else 0
        out["security_level"] = SEC_LEVELS.get(att_sec, f"Unknown ({att_sec})")

        # [4] attestationChallenge
        out["challenge"]       = top[4][3].decode("utf-8", errors="replace")
        out["challenge_match"] = (out["challenge"] == expected_challenge)

        sw_list  = seq_items(top[6][3])
        tee_list = seq_items(top[7][3])

        # RootOfTrust [704]
        rot_raw = find_ctx(tee_list, 704)
        if rot_raw is not None:
            _, _, _, rot_seq, _ = parse_tlv(rot_raw, 0)
            rot = seq_items(rot_seq)
            if len(rot) >= 3:
                locked = rot[1][3][0] != 0 if rot[1][3] else False
                out["bootloader"] = "LOCKED" if locked else "UNLOCKED"
                bs = int.from_bytes(rot[2][3], "big") if rot[2][3] else -1
                out["boot_state"] = BOOT_STATES.get(bs, f"Unknown ({bs})")

        # attestationApplicationId [709] / [703]
        app_id_raw = (find_ctx(sw_list,  709) or find_ctx(sw_list,  703) or
                      find_ctx(tee_list, 709) or find_ctx(tee_list, 703))
        if app_id_raw is not None:
            if app_id_raw[0] == 0x04:
                _, _, _, app_id_raw, _ = parse_tlv(app_id_raw, 0)
            _, _, _, app_id_seq, _ = parse_tlv(app_id_raw, 0)
            app_id_top = seq_items(app_id_seq)
            if len(app_id_top) >= 2:
                # [0] SET OF PackageInfo { packageName OCTET STRING, version INTEGER }
                pkg_set = seq_items(app_id_top[0][3])
                if pkg_set:
                    pkg = seq_items(pkg_set[0][3])
                    if len(pkg) >= 2:
                        out["package_name"]    = pkg[0][3].decode("utf-8", errors="replace")
                        out["package_version"] = str(int.from_bytes(pkg[1][3], "big"))
                # [1] SET OF signatureDigest OCTET STRING
                out["fingerprints"] = [it[3].hex().upper() for it in seq_items(app_id_top[1][3])]

        # ── Evaluate hardware trust ───────────────────────────────────────────
        if att_sec == 0:
            out["reason"] = "Software-only attestation — no hardware security guarantee"
        elif not out["challenge_match"]:
            out["reason"] = (f"Challenge mismatch (expected '{expected_challenge}', "
                             f"got '{out['challenge']}')")
        elif out["bootloader"] != "LOCKED":
            out["reason"] = "Bootloader is UNLOCKED"
        elif not out["boot_state"].startswith("Verified"):
            out["reason"] = f"Verified boot state is '{out['boot_state']}' (must be Verified/Green)"
        else:
            out["ok"] = True

        return out

    except Exception as e:
        out["reason"] = f"Parse error: {type(e).__name__}: {e}"
        return out

# ── Flask endpoints ────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"trusted": False, "verdict": "ERROR",
                        "reason": "Invalid or missing JSON body", "details": []}), 400

    challenge  = data.get("challenge", "")
    certs_data = data.get("certificates", [])
    if not certs_data:
        return jsonify({"trusted": False, "verdict": "DEVICE_NOT_TRUSTED",
                        "reason": "No certificates provided", "details": []})

    try:
        certs = [x509.load_der_x509_certificate(bytes.fromhex(e["derHex"])) for e in certs_data]
    except Exception as e:
        return jsonify({"trusted": False, "verdict": "ERROR",
                        "reason": f"Certificate decode error: {e}", "details": []}), 400

    # Run all checks (always, so we can report every field) ──────────────────────
    att                    = parse_attestation(certs[0], challenge)
    chain_ok, chain_reason = verify_chain(certs)
    revoked, rev_status    = check_revocation(certs[0])

    fps       = att["fingerprints"]
    apk_match = any(fp == TRUSTED_APK_FINGERPRINT for fp in fps)
    apk_shown = colonize(fps[0]) if fps else "NOT FOUND"

    # ── Build the ordered detail list for the UI ─────────────────────────────────
    details = [
        {"label": "Challenge",            "value": att["challenge"]},
        {"label": "Security Level",       "value": att["security_level"]},
        {"label": "Verified Boot State",  "value": att["boot_state"]},
        {"label": "Bootloader State",     "value": att["bootloader"]},
        {"label": "Package Name",         "value": att["package_name"] or "?"},
        {"label": "Package Version",      "value": att["package_version"] or "?"},
        {"label": "APK Signature SHA-256", "value": apk_shown},
        {"label": "APK Signature Match",  "value": "MATCHED" if apk_match else "MISMATCH"},
        {"label": "Chain Length",         "value": str(len(certs))},
        {"label": "Root CA",              "value": certs[-1].subject.rfc4514_string()},
        {"label": "Chain Integrity",      "value": "VERIFIED" if chain_ok else f"FAILED ({chain_reason})"},
        {"label": "Challenge Match",      "value": "MATCHED" if att["challenge_match"] else "MISMATCH"},
        {"label": "Revocation Check",     "value": rev_status},
    ]

    # ── Decide the verdict (priority order) ──────────────────────────────────────
    if not chain_ok:
        verdict, reason, trusted = "DEVICE_NOT_TRUSTED", chain_reason, False
    elif revoked:
        verdict, reason, trusted = "DEVICE_NOT_TRUSTED", rev_status, False
    elif not att["ok"]:
        verdict, reason, trusted = "DEVICE_NOT_TRUSTED", att["reason"], False
    elif not apk_match:
        verdict, reason, trusted = "APP_TAMPERED", f"APK signature mismatch. Got: {apk_shown}", False
    else:
        verdict, reason, trusted = "DEVICE_TRUSTED", "", True

    return jsonify({"trusted": trusted, "verdict": verdict, "reason": reason, "details": details})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

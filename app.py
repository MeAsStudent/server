#!/usr/bin/env python3
"""
Android Key Attestation verification server.

POST /verify
  Body : { "challenge": "...", "certificates": [{"derHex": "..."}, ...] }
  Reply: { "trusted": bool, "verdict": str, "reason": str }

Verdicts:
  DEVICE_TRUSTED    — all checks pass
  APP_TAMPERED      — hardware OK, but APK signing cert doesn't match
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
# Set TRUSTED_APK_FINGERPRINT as an env var on Render, or leave the default below.
TRUSTED_APK_FINGERPRINT = os.environ.get(
    "TRUSTED_APK_FINGERPRINT",
    "B4D8862F2E9625AF8BBC3E7C70FE2222A56573999BE76A121F62CCC0241DA8D9"
).upper()

ATTESTATION_OID       = "1.3.6.1.4.1.11129.2.1.17"
GOOGLE_REVOCATION_URL = "https://android.googleapis.com/attestation/status"

# ── ASN.1 TLV helpers ──────────────────────────────────────────────────────────

def parse_tlv(data: bytes, offset: int = 0):
    """
    Parse one TLV (Tag-Length-Value) starting at offset.
    Returns (tag_class, constructed, tag_num, value_bytes, next_offset).
    Handles both short-form and long-form tags/lengths.
    """
    b0 = data[offset]; offset += 1
    tag_class   = (b0 >> 6) & 3        # 0=universal, 1=application, 2=context, 3=private
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
    """Parse all TLVs inside a SEQUENCE / SET value (data = content bytes, no outer TL)."""
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
    """
    Verify that each cert is signed by the next one in the chain,
    and that the root CA is a known Google Android attestation CA.
    """
    for i in range(len(certs) - 1):
        sub     = certs[i]
        iss_pub = certs[i + 1].public_key()
        try:
            if isinstance(iss_pub, ec.EllipticCurvePublicKey):
                iss_pub.verify(
                    sub.signature,
                    sub.tbs_certificate_bytes,
                    ec.ECDSA(sub.signature_hash_algorithm)
                )
            elif isinstance(iss_pub, rsa.RSAPublicKey):
                iss_pub.verify(
                    sub.signature,
                    sub.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sub.signature_hash_algorithm
                )
            else:
                return False, f"Unsupported key type at cert[{i + 1}]"
        except InvalidSignature:
            return False, f"cert[{i}] is not signed by cert[{i + 1}]"

    root_subj = certs[-1].subject.rfc4514_string()
    if not ("O=Google LLC" in root_subj and "OU=Android" in root_subj):
        return False, f"Root CA is not a Google Android CA: {root_subj}"

    return True, ""

# ── 2. Revocation check ────────────────────────────────────────────────────────

def check_revocation(cert) -> tuple:
    """
    Check Google's live revocation list for the leaf certificate's serial number.
    Fails open on network errors (logs a warning in production — add proper logging).
    """
    serial_hex = format(cert.serial_number, "X").upper()
    try:
        r = requests.get(GOOGLE_REVOCATION_URL, timeout=5)
        if r.status_code == 200:
            entries = r.json().get("entries", {})
            entry   = entries.get(serial_hex) or entries.get(serial_hex.lower())
            if entry:
                return True, f"Certificate revoked: {entry.get('reason', 'unknown reason')}"
    except Exception:
        pass    # Network failure → fail open; add logging here for production
    return False, ""

# ── 3. Attestation extension parsing ──────────────────────────────────────────

def parse_attestation(cert, expected_challenge: str) -> dict:
    """
    Parse the Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).

    Checks:
      - attestationSecurityLevel must be TEE (1) or StrongBox (2), NOT Software (0)
      - challenge bytes must match expected_challenge
      - deviceLocked must be True
      - verifiedBootState must be 0 (Verified / Green)
      - attestationApplicationId contains the APK signing cert SHA-256

    Returns dict with 'ok' key. If ok=True, also contains 'fingerprints' list.
    """
    # ── Extract extension raw bytes ────────────────────────────────────────────
    raw = None
    for ext in cert.extensions:
        if ext.oid.dotted_string == ATTESTATION_OID:
            raw = ext.value.value   # DER bytes of KeyDescription (may or may not include outer OCTET STRING wrapper)
            break
    if raw is None:
        return {"ok": False, "reason": "Attestation extension not found in leaf certificate"}

    # Some versions of the cryptography library return the OCTET STRING TLV; unwrap it.
    if raw[0] == 0x04:
        _, _, _, raw, _ = parse_tlv(raw, 0)

    try:
        # ── Outer SEQUENCE (KeyDescription) ───────────────────────────────────
        _, _, _, seq_val, _ = parse_tlv(raw, 0)
        top = seq_items(seq_val)

        if len(top) < 8:
            return {"ok": False, "reason": f"KeyDescription has {len(top)} elements (expected ≥ 8)"}

        # ── [1] attestationSecurityLevel ENUMERATED ────────────────────────────
        att_sec = int.from_bytes(top[1][3], "big") if top[1][3] else 0
        if att_sec == 0:
            return {"ok": False, "reason": "Software-only attestation — no hardware security guarantee"}

        # ── [4] attestationChallenge OCTET STRING ──────────────────────────────
        challenge = top[4][3].decode("utf-8", errors="replace")
        if challenge != expected_challenge:
            return {
                "ok": False,
                "reason": f"Challenge mismatch (expected '{expected_challenge}', got '{challenge}')"
            }

        # ── softwareEnforced [6] and teeEnforced [7] SEQUENCE ─────────────────
        sw_list  = seq_items(top[6][3])
        tee_list = seq_items(top[7][3])

        # ── RootOfTrust tag [704] — EXPLICIT SEQUENCE ─────────────────────────
        rot_raw = find_ctx(tee_list, 704)
        if rot_raw is None:
            return {"ok": False, "reason": "RootOfTrust (tag 704) not found in teeEnforced"}

        # rot_raw contains the inner SEQUENCE TLV (explicit tagging)
        _, _, _, rot_seq, _ = parse_tlv(rot_raw, 0)
        rot = seq_items(rot_seq)

        if len(rot) < 3:
            return {"ok": False, "reason": f"RootOfTrust has only {len(rot)} fields (expected ≥ 3)"}

        # rot[1] = BOOLEAN deviceLocked
        device_locked = rot[1][3][0] != 0 if rot[1][3] else False
        if not device_locked:
            return {"ok": False, "reason": "Bootloader is UNLOCKED"}

        # rot[2] = ENUMERATED verifiedBootState (0=Verified, 1=SelfSigned, 2=Unverified, 3=Failed)
        boot_state  = int.from_bytes(rot[2][3], "big") if rot[2][3] else -1
        boot_labels = {0: "Verified (Green)", 1: "Self-Signed (Yellow)", 2: "Unverified (Orange)", 3: "Failed (Red)"}
        if boot_state != 0:
            label = boot_labels.get(boot_state, str(boot_state))
            return {"ok": False, "reason": f"Verified boot state is '{label}' (must be Verified/Green)"}

        # ── attestationApplicationId tag [709] (KeyMint) or [703] (Keymaster) ─
        # Try softwareEnforced first (where most devices put it), then teeEnforced.
        app_id_raw = (find_ctx(sw_list,  709) or find_ctx(sw_list,  703) or
                      find_ctx(tee_list, 709) or find_ctx(tee_list, 703))

        if app_id_raw is None:
            return {"ok": False, "reason": "attestationApplicationId (tag 703/709) not found"}

        # Handle explicit tagging (starts with OCTET STRING 0x04) vs implicit (starts with SEQUENCE 0x30)
        if app_id_raw[0] == 0x04:
            _, _, _, app_id_raw, _ = parse_tlv(app_id_raw, 0)

        # app_id_raw is now the DER bytes of AttestationApplicationId SEQUENCE
        _, _, _, app_id_seq, _ = parse_tlv(app_id_raw, 0)
        app_id_top = seq_items(app_id_seq)   # [SET OF PackageInfo, SET OF signatureDigests]

        if len(app_id_top) < 2:
            return {"ok": False, "reason": "AttestationApplicationId is malformed (< 2 elements)"}

        # app_id_top[1] = SET OF OCTET STRING (SHA-256 of each signing certificate)
        sig_set      = seq_items(app_id_top[1][3])
        fingerprints = [item[3].hex().upper() for item in sig_set]

        return {
            "ok":          True,
            "att_sec":     att_sec,
            "boot_state":  boot_state,
            "fingerprints": fingerprints
        }

    except Exception as e:
        return {"ok": False, "reason": f"Parse error: {type(e).__name__}: {e}"}

# ── Flask endpoints ────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"trusted": False, "verdict": "ERROR", "reason": "Invalid or missing JSON body"}), 400

    challenge  = data.get("challenge", "")
    certs_data = data.get("certificates", [])

    if not certs_data:
        return jsonify({"trusted": False, "verdict": "DEVICE_NOT_TRUSTED", "reason": "No certificates provided"})

    # Parse certificates from DER hex
    certs = []
    try:
        for entry in certs_data:
            der = bytes.fromhex(entry["derHex"])
            certs.append(x509.load_der_x509_certificate(der))
    except Exception as e:
        return jsonify({"trusted": False, "verdict": "ERROR", "reason": f"Certificate decode error: {e}"}), 400

    # Step 1: Chain signature verification + root CA check
    chain_ok, chain_reason = verify_chain(certs)
    if not chain_ok:
        return jsonify({"trusted": False, "verdict": "DEVICE_NOT_TRUSTED", "reason": chain_reason})

    # Step 2: Revocation check (leaf cert)
    revoked, rev_reason = check_revocation(certs[0])
    if revoked:
        return jsonify({"trusted": False, "verdict": "DEVICE_NOT_TRUSTED", "reason": rev_reason})

    # Step 3: Attestation extension — challenge, TEE level, boot state, bootloader lock
    att = parse_attestation(certs[0], challenge)
    if not att["ok"]:
        return jsonify({"trusted": False, "verdict": "DEVICE_NOT_TRUSTED", "reason": att["reason"]})

    # Step 4: APK signing cert fingerprint check
    fingerprints = att.get("fingerprints", [])
    if not any(fp == TRUSTED_APK_FINGERPRINT for fp in fingerprints):
        got = fingerprints[0] if fingerprints else "NOT_FOUND"
        return jsonify({
            "trusted": False,
            "verdict": "APP_TAMPERED",
            "reason":  f"APK signature mismatch. Got: {got}"
        })

    return jsonify({"trusted": True, "verdict": "DEVICE_TRUSTED", "reason": ""})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

#!/usr/bin/python3
############################################################################
# ========================================================================
# Copyright (c) 2026 Broadcom Inc. and/or its subsidiaries.
# All Rights Reserved. Broadcom Confidential.
# ========================================================================
###
# The file name has hyphens, as Avi ControlScripts are usually named; it isn't
# imported as a module, so pylint's module naming rule doesn't apply.
# pylint: disable=invalid-name
# A ControlScript must be a single file, so it can't be split into
# modules to keep it under pylint's line limit.
# pylint: disable=too-many-lines
"""Avi ControlScript: add a new Service Engine VM to a DRS anti-affinity rule.

Triggered by an Avi alert on the CREATED_SE event. Avi passes the alert as a
JSON string via stdin, sys.argv[1]. The script:

1. Reads the SE VM name, SE group name and cloud name from the event.
2. Connects to vCenter and finds the SE VM and the cluster it runs in.
3. Asks the Avi API which Service Engines are in the SE group. If there are
    fewer than two, there's nothing to keep apart, and the script stops.
4. Puts the VMs of all of the group's SEs in the cluster, including the
    new one, in the DRS VM-VM anti-affinity rule
    ``avi_se_antiaffinity_<controller>_<cloud>_<se group>``, creating the
    rule if it doesn't exist yet. VMs already in the rule aren't added
    again. ``<controller>`` is the Avi controller cluster's name, from
    /api/cluster.

vCenter credentials
-------------------
On the controller, the credentials are a JSON file (``vcenter``,
``username``, ``password``) encrypted to the public key of an Avi SSL
certificate and uploaded with the fileobject API. The script downloads the
fileobject, fetches the matching private key from the sslkeyandcertificate
object, and decrypts it in memory. Encrypt the file with:

    openssl cms -encrypt -in credentials.json -out credentials.json.enc \
        -recip controlscript_cert.pem -aes256

where controlscript_cert.pem is the certificate exported from Avi. openssl's
default S/MIME output is expected, but -outform PEM or DER also works.
Upload credentials.json.enc as a fileobject named vcentercredentials.json.enc.

Configure the script with --credentials-cert (or AVI_CREDENTIALS_CERT). The
file is downloaded from the fileobject named vcentercredentials.json.enc
(looked up by name, then fetched from /api/fileobject/<uuid>/download); to
use a different fileobject, set --fileobject-download-path (or
FILEOBJECT_DOWNLOAD_PATH) to its name.

To test locally, pass the event, a local credentials file (plain JSON, or
encrypted together with --key-file) and the SE group's SE names:

    python avi-controlscript-se-antiaffinitygroup.py \
        --event-file event_data.json \
        --credentials-file credentials.json.enc \
        --key-file controlscript_key.pem \
        --cert-file controlscript_cert.pem \
        --se-group-members slb-se-eyiec slb-se-abcde \
        --dry-run
"""

import argparse
import base64
import email
import json
import logging
import os
import sys
import warnings
from typing import Optional

import urllib3
from avi.sdk.avi_api import ApiSession
from cryptography import x509
from cryptography.hazmat.primitives import (
    hashes,
    keywrap,
    padding,
    serialization,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import pkcs7
from pyVim.connect import Disconnect, SmartConnect
from pyVim.task import WaitForTask
from pyVmomi import vim

log = logging.getLogger("se-antiaffinity")

# The start of the warning the Avi SDK logs and raises for every session made
# with verify=False (see quiet_ssl_warnings).
AVI_SDK_VERIFY_WARNING = "Strong Recommendation: It is highly recommended"

# DER content of the CMS object identifiers the fallback decryption reads.
OID_ENVELOPED_DATA = bytes.fromhex("2a864886f70d010703")  # 1.2.840.113549.1.7.3
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1
# AES-CBC key sizes in bytes, by object identifier (2.16.840.1.101.3.4.1.x).
OID_AES_CBC_KEY_SIZES = {
    bytes.fromhex("608648016503040102"): 16,  # aes128-CBC
    bytes.fromhex("608648016503040116"): 24,  # aes192-CBC
    bytes.fromhex("60864801650304012a"): 32,  # aes256-CBC
}
# openssl cms uses SHA-1 in its default EC key agreement scheme, so files
# made with it need SHA-1 to decrypt. It only derives a key here; no
# signature relies on it.
SHA1_FOR_KDF = hashes.SHA1()  # nosec B303
# ECDH key agreement schemes (RFC 5753), by object identifier: the hash
# their X9.63 KDF uses. The cofactor schemes give the same result as the
# standard ones on the NIST prime curves, which have a cofactor of 1.
OID_ECDH_KDF_HASHES = {
    bytes.fromhex("2b81051086483f0002"): SHA1_FOR_KDF,  # stdDH-sha1kdf
    bytes.fromhex("2b8104010b00"): hashes.SHA224(),  # stdDH-sha224kdf
    bytes.fromhex("2b8104010b01"): hashes.SHA256(),  # stdDH-sha256kdf
    bytes.fromhex("2b8104010b02"): hashes.SHA384(),  # stdDH-sha384kdf
    bytes.fromhex("2b8104010b03"): hashes.SHA512(),  # stdDH-sha512kdf
    bytes.fromhex("2b81051086483f0003"): SHA1_FOR_KDF,  # cofactorDH-sha1kdf
    bytes.fromhex("2b8104010e00"): hashes.SHA224(),  # cofactorDH-sha224kdf
    bytes.fromhex("2b8104010e01"): hashes.SHA256(),  # cofactorDH-sha256kdf
    bytes.fromhex("2b8104010e02"): hashes.SHA384(),  # cofactorDH-sha384kdf
    bytes.fromhex("2b8104010e03"): hashes.SHA512(),  # cofactorDH-sha512kdf
}
# AES key wrap key sizes in bytes, by object identifier.
OID_AES_WRAP_KEY_SIZES = {
    bytes.fromhex("608648016503040105"): 16,  # aes128-wrap
    bytes.fromhex("608648016503040119"): 24,  # aes192-wrap
    bytes.fromhex("60864801650304012d"): 32,  # aes256-wrap
}

# Name of the fileobject holding the encrypted credentials.
# FILEOBJECT_DOWNLOAD_PATH (CLI or environment) overrides it.
DEFAULT_CREDENTIALS_FILENAME = "vcentercredentials.json.enc"

# Settings for running on the controller. An alert-triggered ControlScript
# gets only the alert JSON, no other arguments or environment variables, so
# edit these before uploading the script.

# Avi certificate whose key decrypts the credentials file.
DEFAULT_CREDENTIALS_CERT = "controlscript-cert"
# vCenter's certificate is usually signed by its own CA (VMCA), which the
# controller doesn't trust, so it isn't verified by default. Set True to
# verify it.
VERIFY_VCENTER_CERT = False


def parse_event(
    event_data: dict,
) -> tuple[str, str, Optional[str], Optional[str]]:
    """Get the SE, SE group and cloud from an Avi CREATED_SE alert.

    Args:
        event_data (dict): The alert payload Avi passes to the ControlScript.

    Returns:
        tuple: The SE name as known to vCenter (e.g. avi-se-abcde), the SE
            group name, the cloud name, and the SE group's UUID (the
            event's obj_uuid). The cloud name and UUID are None if the event
            doesn't have them.
    """
    for event in event_data.get("events", []):
        details = event.get("event_details", {}).get("spawn_se_details")
        if event.get("event_id") == "CREATED_SE" and details:
            obj_uuid = event.get("obj_uuid") or ""
            return (
                details["se_name"],
                details["se_grp_name"],
                details.get("cloud_name"),
                (obj_uuid if obj_uuid.startswith("serviceenginegroup-") else None),
            )
    raise ValueError("No CREATED_SE event with spawn_se_details found in the alert payload")


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments.

    Avi runs a ControlScript as ``script '<alert json>'``, so a first
    argument that looks like JSON is taken as the event payload and the rest
    is parsed normally.

    Args:
        argv (list): Arguments, without the program name.

    Returns:
        argparse.Namespace: Parsed arguments. ``event`` holds the event dict,
            if one was given.
    """
    event = None
    if argv and argv[0].lstrip().startswith("{"):
        event = json.loads(argv[0])
        argv = argv[1:]

    parser = argparse.ArgumentParser(
        description=("Update vSphere DRS anti-affinity rule with a new Avi Service " "Engine")
    )
    parser.add_argument(
        "--event-file",
        help="Read the Avi alert JSON from this file (for testing).",
    )
    parser.add_argument("-se", "--se-vm-name", help="Override the SE VM name from the event.")
    parser.add_argument(
        "-seg",
        "--service-engine-group",
        help="Override the SE group name from the event.",
    )
    parser.add_argument(
        "--fileobject-download-path",
        default=os.environ.get("FILEOBJECT_DOWNLOAD_PATH", DEFAULT_CREDENTIALS_FILENAME),
        help=(
            "Name of the Avi fileobject holding the encrypted credentials "
            f"(default: {DEFAULT_CREDENTIALS_FILENAME}). Also read from "
            "FILEOBJECT_DOWNLOAD_PATH."
        ),
    )
    parser.add_argument(
        "--credentials-cert",
        default=os.environ.get("AVI_CREDENTIALS_CERT", DEFAULT_CREDENTIALS_CERT),
        help=("Name of the Avi sslkeyandcertificate whose key decrypts the " "credentials file."),
    )
    parser.add_argument(
        "--credentials-file",
        help=("Use a local credentials file instead of the Avi fileobject " "(for testing)."),
    )
    parser.add_argument(
        "--key-file",
        help=("PEM private key to decrypt --credentials-file with " "(for testing)."),
    )
    parser.add_argument(
        "--cert-file",
        help="PEM certificate matching --key-file (for testing).",
    )
    parser.add_argument("--cloud-name", help="Override the Avi cloud name from the event.")
    parser.add_argument(
        "--controller-fqdn",
        help=(
            "Controller name to use in the rule name, instead of asking the "
            "Avi API for the controller cluster's name (for testing)."
        ),
    )
    parser.add_argument(
        "--se-group-members",
        nargs="+",
        metavar="SE_NAME",
        help=("Names of the SEs in the SE group, instead of asking the Avi " "API (for testing)."),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Skip vCenter TLS certificate validation even if " "VERIFY_VCENTER_CERT is True (it's False by default)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without changing it.",
    )
    args = parser.parse_args(argv)

    if args.event_file:
        with open(args.event_file, encoding="utf-8") as f:
            event = json.load(f)
    args.event = event
    return args


def get_avi_session():
    """Open an API session to the local controller.

    Uses the API token and user Avi gives the ControlScript. ControlScripts
    run in a container, so the controller API is reached at the container's
    gateway address, which Avi passes in DOCKER_GATEWAY.
    """
    token = os.environ.get("API_TOKEN")
    user = os.environ.get("USER")
    if not token or not user:
        raise RuntimeError("API_TOKEN/USER not set: not running as an Avi ControlScript " "(use --credentials-file)")
    controller = os.environ.get("DOCKER_GATEWAY")
    if not controller:
        raise RuntimeError("DOCKER_GATEWAY not set: can't find the Avi controller API")
    return ApiSession.get_session(
        controller,
        user,
        token=token,
        tenant=os.environ.get("TENANT", "admin"),
    )


def get_fileobject_contents(session, name: str) -> bytes:
    """Download the contents of the named fileobject.

    GET /api/fileobject?name=<name> only returns the object's JSON
    description, so this looks up the fileobject's UUID there, then downloads
    the file from /api/fileobject/<uuid>/download.
    """
    obj = session.get_object_by_name("fileobject", name)
    if not obj:
        raise RuntimeError(f"Fileobject '{name}' not found")

    rsp = session.get(f"fileobject/{obj['uuid']}/download")
    if rsp.status_code != 200:
        raise RuntimeError(f"Couldn't download fileobject '{name}': " f"HTTP {rsp.status_code} {rsp.text[:200]}")

    # The API docs label the response application/json; if the file comes
    # back as a JSON string rather than raw bytes, unwrap it.
    if "json" in rsp.headers.get("Content-Type", ""):
        try:
            body = rsp.json()
        except ValueError:
            body = None
        if isinstance(body, str):
            return body.encode()
    return rsp.content


def get_key_and_cert(session, cert_name: str):
    """Return the private key and certificate of an Avi certificate."""
    obj = session.get_object_by_name("sslkeyandcertificate", cert_name, params={"export_key": True})
    if not obj:
        raise RuntimeError(f"Certificate '{cert_name}' not found")
    key_pem = obj.get("key")
    if not key_pem or key_pem == "<sensitive>":
        raise RuntimeError(
            f"Avi didn't return the private key for '{cert_name}'; " "check the script user's permissions"
        )
    passphrase = obj.get("key_passphrase")
    key = serialization.load_pem_private_key(key_pem.encode(), password=passphrase.encode() if passphrase else None)
    cert = x509.load_pem_x509_certificate(obj["certificate"]["certificate"].encode())
    return key, cert


def decrypt_credentials(encrypted: bytes, key, cert) -> bytes:
    """Decrypt a CMS/PKCS#7 enveloped file made with ``openssl cms -encrypt``.

    Handles openssl's default S/MIME output as well as ``-outform PEM`` and
    ``-outform DER``, for RSA and EC certificates. Uses cryptography's PKCS#7
    decryption where it can: cryptography 44 and later, with an RSA key.
    Everything else uses decrypt_cms_fallback: older cryptography versions,
    such as the one on some Avi controllers, EC keys (which cryptography's
    PKCS#7 decryption doesn't support), and files cryptography can't parse,
    such as the indefinite-length BER that ``openssl cms -stream`` writes.
    """
    if not hasattr(pkcs7, "pkcs7_decrypt_der") or not isinstance(key, rsa.RSAPrivateKey):
        return decrypt_cms_fallback(cms_to_der(encrypted), key, cert)
    try:
        return decrypt_cms_with_cryptography(encrypted, key, cert)
    except ValueError:
        return decrypt_cms_fallback(cms_to_der(encrypted), key, cert)


def decrypt_cms_with_cryptography(encrypted: bytes, key, cert) -> bytes:
    """Decrypt S/MIME, PEM or DER CMS data with cryptography 44 or later."""
    head = encrypted.lstrip()[:200]
    if head.startswith(b"MIME-Version:") or head.startswith(b"Content-"):
        return pkcs7.pkcs7_decrypt_smime(encrypted, cert, key, [])
    if head.startswith(b"-----BEGIN"):
        # openssl cms writes "CMS" PEM headers; cryptography expects "PKCS7"
        pem = encrypted.replace(b"BEGIN CMS", b"BEGIN PKCS7").replace(b"END CMS", b"END PKCS7")
        return pkcs7.pkcs7_decrypt_pem(pem, cert, key, [])
    return pkcs7.pkcs7_decrypt_der(encrypted, cert, key, [])


def cms_to_der(encrypted: bytes) -> bytes:
    """Return the DER (or BER) bytes of an S/MIME, PEM or DER CMS file."""
    head = encrypted.lstrip()[:200]
    if head.startswith(b"MIME-Version:") or head.startswith(b"Content-"):
        payload = email.message_from_bytes(encrypted).get_payload(decode=True)
        if not payload or not isinstance(payload, bytes):
            raise ValueError("S/MIME file has no encrypted content")
        return payload
    if head.startswith(b"-----BEGIN"):
        body = b"".join(line for line in encrypted.strip().splitlines() if not line.startswith(b"-----"))
        return base64.b64decode(body)
    return encrypted


def ber_element(data: bytes, pos: int) -> tuple[int, bytes, bytes, int]:
    """Read one BER element starting at ``pos``.

    Returns:
        tuple: The tag byte, the element's contents, the whole element
            (tag and length included), and the position after it.
    """
    if pos + 2 > len(data):
        raise ValueError("Truncated CMS data")
    start, tag, length = pos, data[pos], data[pos + 1]
    if tag & 0x1F == 0x1F:
        raise ValueError("Unsupported multi-byte BER tag in CMS data")
    pos += 2
    if length == 0x80:
        # Indefinite length (openssl cms -stream): read the elements
        # inside until the end-of-contents marker.
        contents_start = pos
        while not data.startswith(b"\0\0", pos):
            pos = ber_element(data, pos)[3]
        end = pos + 2
        return tag, data[contents_start:pos], data[start:end], end
    if length & 0x80:
        size_end = pos + (length & 0x7F)
        length = int.from_bytes(data[pos:size_end], "big")
        pos = size_end
    end = pos + length
    if end > len(data):
        raise ValueError("Truncated CMS data")
    return tag, data[pos:end], data[start:end], end


def ber_children(data: bytes) -> list[tuple[int, bytes, bytes]]:
    """Read the BER elements in ``data``: (tag, contents, whole element)."""
    children, pos = [], 0
    while pos < len(data):
        tag, contents, whole, pos = ber_element(data, pos)
        children.append((tag, contents, whole))
    return children


def ber_octets(tag: int, contents: bytes) -> bytes:
    """Return an OCTET STRING's bytes, joining the chunks of a constructed one.

    openssl cms -stream writes the encrypted content in chunks.
    """
    if tag & 0x20:
        return b"".join(ber_octets(t, c) for t, c, _ in ber_children(contents))
    return contents


def ber_first(children, tag: int) -> bytes:
    """Return the contents of the first child with this tag."""
    for child_tag, contents, _ in children:
        if child_tag == tag:
            return contents
    raise ValueError(f"CMS data is missing an element with tag 0x{tag:02x}")


def der_encode(tag: int, *parts: bytes) -> bytes:
    """Encode one DER element from its tag and contents."""
    body = b"".join(parts)
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def cert_subject_key_id(cert) -> Optional[bytes]:
    """Return the certificate's subject key identifier, if it has one."""
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return None


def recipient_matches(rid_tag: int, rid: bytes, rid_whole: bytes, cert):
    """Whether a CMS recipient identifier names ``cert``.

    The identifier is the issuer and serial number (openssl's default), or
    the subject key identifier (openssl cms -keyid): tagged [0] for an RSA
    recipient, or [0] around a RecipientKeyIdentifier for an EC one.
    """
    if rid_tag == 0x30:
        issuer_and_serial = ber_children(rid)
        issuer, serial = issuer_and_serial[0], issuer_and_serial[1]
        return (
            issuer[2] == cert.issuer.public_bytes()
            and int.from_bytes(serial[1], "big", signed=True) == cert.serial_number
        )
    if rid_tag == 0x80:
        return rid == cert_subject_key_id(cert)
    if rid_tag == 0xA0:
        return ber_children(rid)[0][1] == cert_subject_key_id(cert)
    raise ValueError(f"Unsupported CMS recipient identifier: {rid_whole[:1].hex()}")


def cms_enveloped_fields(der: bytes) -> list[tuple[int, bytes, bytes]]:
    """Return the fields of the EnvelopedData inside a CMS ContentInfo."""
    content_info = ber_children(ber_children(der)[0][1])
    if content_info[0][1] != OID_ENVELOPED_DATA:
        raise ValueError("CMS data isn't enveloped (encrypted) data")
    enveloped = ber_children(content_info[1][1])[0]
    return ber_children(enveloped[1])


def rsa_recipient_content_key(recipient: bytes, key, cert) -> Optional[bytes]:
    """Decrypt the content key from a KeyTransRecipientInfo (RSA).

    Returns None if the recipient isn't ``cert``.
    """
    fields = ber_children(recipient)
    rid, alg, enc_key = fields[1], fields[2], fields[3]
    if not recipient_matches(rid[0], rid[1], rid[2], cert):
        return None
    if ber_children(alg[1])[0][1] != OID_RSA_ENCRYPTION:
        raise ValueError("Unsupported CMS key encryption (only RSA PKCS#1 v1.5, " "openssl's default, is supported)")
    return key.decrypt(ber_octets(enc_key[0], enc_key[1]), rsa_padding.PKCS1v15())


def ec_key_encryption_key(key, point: bytes, ukm: Optional[bytes], key_agreement: bytes) -> bytes:
    """Derive the AES key-encryption key for an EC recipient (RFC 5753).

    Args:
        key: The recipient's EC private key.
        point: The sender's one-off EC public key, as an encoded point.
        ukm: The user keying material, if the file has any.
        key_agreement: The keyEncryptionAlgorithm's contents: the key
            agreement scheme and key wrap algorithm.
    """
    scheme = ber_children(key_agreement)
    kdf_hash = OID_ECDH_KDF_HASHES.get(scheme[0][1])
    wrap = scheme[1]
    kek_size = OID_AES_WRAP_KEY_SIZES.get(ber_children(wrap[1])[0][1])
    if kdf_hash is None or kek_size is None:
        raise ValueError("Unsupported CMS key agreement (only ECDH with an X9.63 KDF and " "AES key wrap is supported)")
    shared = key.exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(key.curve, point),
    )
    # ECC-CMS-SharedInfo: the key wrap algorithm, the user keying material
    # if any, and the key-encryption key's size in bits.
    shared_info = der_encode(
        0x30,
        wrap[2],
        der_encode(0xA0, der_encode(0x04, ukm)) if ukm else b"",
        der_encode(0xA2, der_encode(0x04, (kek_size * 8).to_bytes(4, "big"))),
    )
    return X963KDF(kdf_hash, kek_size, shared_info).derive(shared)


def ec_recipient_content_key(recipient: bytes, key, cert) -> Optional[bytes]:
    """Unwrap the content key from a KeyAgreeRecipientInfo (EC, RFC 5753).

    The sender made a one-off EC key pair; ECDH between its public key and
    ``key`` gives a shared secret, the X9.63 KDF turns that into an AES
    key-encryption key, and that unwraps the content key. Returns None if
    the recipient isn't ``cert``.
    """
    fields = ber_children(recipient)
    # originator [0] holds originatorKey [1]: the sender's one-off key.
    originator = ber_children(fields[1][1])[0]
    if originator[0] != 0xA1:
        raise ValueError(
            "Unsupported CMS key agreement originator (only a one-off " "public key, openssl's default, is supported)"
        )
    # The BIT STRING's first byte counts unused bits; the point follows.
    point = ber_children(originator[1])[1][1][1:]
    rest = fields[2:]
    ukm = None
    if rest[0][0] == 0xA1:  # optional user keying material
        ukm_octets = ber_children(rest[0][1])[0]
        ukm = ber_octets(ukm_octets[0], ukm_octets[1])
        rest = rest[1:]

    for _, encrypted_key, _ in ber_children(rest[1][1]):
        rid_and_key = ber_children(encrypted_key)
        rid, wrapped = rid_and_key[0], rid_and_key[1]
        if recipient_matches(rid[0], rid[1], rid[2], cert):
            kek = ec_key_encryption_key(key, point, ukm, rest[0][1])
            return keywrap.aes_key_unwrap(kek, ber_octets(wrapped[0], wrapped[1]))
    return None


def cms_content_key(recipient_infos: bytes, key, cert) -> bytes:
    """Return the content key, from the recipient that is ``cert``."""
    for tag, recipient, _ in ber_children(recipient_infos):
        content_key = None
        if tag == 0x30 and isinstance(key, rsa.RSAPrivateKey):
            content_key = rsa_recipient_content_key(recipient, key, cert)
        elif tag == 0xA1 and isinstance(key, ec.EllipticCurvePrivateKey):
            content_key = ec_recipient_content_key(recipient, key, cert)
        if content_key is not None:
            return content_key
    raise ValueError("The credentials file wasn't encrypted to this certificate")


def cms_encrypted_content(content_info: bytes) -> tuple[int, bytes, bytes]:
    """Read an EncryptedContentInfo.

    Returns:
        tuple: The AES key size in bytes, the IV, and the ciphertext.
    """
    fields = ber_children(content_info)
    alg = ber_children(fields[1][1])
    key_size = OID_AES_CBC_KEY_SIZES.get(alg[0][1])
    if key_size is None:
        raise ValueError("Unsupported CMS content encryption (only AES-CBC is supported)")
    return (
        key_size,
        ber_octets(alg[1][0], alg[1][1]),
        ber_octets(fields[2][0], fields[2][1]),
    )


def decrypt_cms_fallback(der: bytes, key, cert) -> bytes:
    """Decrypt CMS enveloped data without cryptography's PKCS#7 decryption.

    Supports what ``openssl cms -encrypt`` writes, in DER or BER: AES-CBC
    content encryption, with the content key encrypted to an RSA
    certificate (PKCS#1 v1.5) or agreed with an EC one (ECDH).
    """
    try:
        fields = cms_enveloped_fields(der)
        content_key = cms_content_key(ber_first(fields, 0x31), key, cert)
        key_size, iv, ciphertext = cms_encrypted_content(ber_first(fields, 0x30))
    except keywrap.InvalidUnwrap as exc:
        raise ValueError(
            "Couldn't decrypt the credentials file: the key agreed with ECDH " "didn't unwrap the content key"
        ) from exc
    except (IndexError, ValueError) as exc:
        raise ValueError(f"Couldn't decrypt the credentials file: {exc}") from exc

    if len(content_key) != key_size:
        raise ValueError("Couldn't decrypt the CMS content key")
    decryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def parse_vcenter_credentials(args) -> tuple[str, str, str]:
    """Load and decrypt the vCenter credentials.

    On the controller, the encrypted file comes from an Avi fileobject and
    the key from an Avi certificate. With --credentials-file, a local file is
    used instead: decrypted with --key-file/--cert-file if given, otherwise
    read as plain JSON.

    Returns:
        tuple: vCenter FQDN, username, password
    """
    if args.credentials_file:
        with open(args.credentials_file, "rb") as f:
            data = f.read()
        if args.key_file:
            if not args.cert_file:
                raise RuntimeError("--key-file needs --cert-file too")
            with open(args.key_file, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(args.cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            data = decrypt_credentials(data, key, cert)
    else:
        if not args.credentials_cert:
            raise RuntimeError("Set --credentials-cert or AVI_CREDENTIALS_CERT to the Avi " "certificate name")
        session = get_avi_session()
        key, cert = get_key_and_cert(session, args.credentials_cert)
        data = decrypt_credentials(
            get_fileobject_contents(session, args.fileobject_download_path),
            key,
            cert,
        )
    creds = json.loads(data)
    return creds["vcenter"], creds["username"], creds["password"]


def find_vm(content, vm_name: str):
    """Return the VM with this exact name, or None."""
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        matches = [vm for vm in view.view if vm.name == vm_name]
    finally:
        view.Destroy()
    if len(matches) > 1:
        raise RuntimeError(f"More than one VM named '{vm_name}' in vCenter")
    return matches[0] if matches else None


def get_cluster(vm) -> vim.ClusterComputeResource:
    """Return the DRS cluster the VM's host belongs to."""
    host = vm.runtime.host
    cluster = host.parent if host else None
    if not isinstance(cluster, vim.ClusterComputeResource):
        raise RuntimeError(f"VM '{vm.name}' is not running on a host in a cluster")
    return cluster


def get_controller_cluster_name(session) -> str:
    """Return the Avi controller cluster's name, from GET /api/cluster.

    Used as the controller FQDN in the rule name, so name the controller
    cluster after its FQDN (Administration > Controller > Nodes > Edit).
    The cluster name is the same whichever controller node runs the script.
    """
    rsp = session.get("cluster")
    if rsp.status_code != 200:
        raise RuntimeError("Couldn't read the controller cluster: " f"HTTP {rsp.status_code} {rsp.text[:200]}")
    name = rsp.json().get("name")
    if not name:
        raise RuntimeError("The Avi controller cluster has no name")
    return name


def ref_uuid(ref: Optional[str]) -> Optional[str]:
    """Return the UUID at the end of an Avi object ref (URL), or None."""
    if not ref:
        return None
    return ref.rsplit("/", 1)[-1].split("#", 1)[0]


def get_se_group_se_names(session, seg_name: str, cloud_name: str, seg_uuid: Optional[str] = None) -> list[str]:
    """Return the names of the Service Engines in an SE group, from Avi.

    Avi names each SE after its VM in vCenter (the se_name in the
    CREATED_SE event), so these are also the SE VM names.

    The SE group is the one with ``seg_uuid`` (from the alert) if given.
    Otherwise it's looked up by name in the cloud: every cloud has its own
    Default-Group, so the name alone may find another cloud's group.

    All SEs are listed and filtered here by their se_group_ref, so the
    result doesn't depend on the API's refers_to filter.
    """
    if not seg_uuid:
        seg = session.get_object_by_name(
            "serviceenginegroup",
            seg_name,
            params={"cloud_ref.name": cloud_name},
        )
        if not seg:
            raise RuntimeError(f"SE group '{seg_name}' not found in cloud '{cloud_name}'")
        seg_uuid = seg["uuid"]
    ses = session.get_objects_iter("serviceengine", params={"fields": "name,se_group_ref"})
    names = [se["name"] for se in ses if ref_uuid(se.get("se_group_ref")) == seg_uuid]
    log.info(
        "Avi API lists %d SE(s) in SE group '%s' (%s): %s",
        len(names),
        seg_name,
        seg_uuid,
        ", ".join(names) or "none",
    )
    return names


def vm_cluster(vm):
    """Return the cluster the VM's host is in, or None."""
    host = vm.runtime.host
    return host.parent if host else None


def find_se_group_vms(content, cluster, vm, se_names) -> list:
    """Find the cluster's VMs for all of the SE group's Service Engines.

    The SEs' VMs are looked up by name in all of vCenter, so that SEs in
    other clusters or missing from vCenter can be reported. Only VMs in
    ``cluster`` are returned, since a DRS rule can only hold VMs of its own
    cluster. The new SE's VM is always included (last), even if Avi doesn't
    list it yet.

    Args:
        se_names: Names of the SEs in the SE group, from the Avi API.
    """
    wanted = set(se_names) - {vm.name}
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        found = [other for other in view.view if other.name in wanted]
    finally:
        view.Destroy()
    others = []
    for other in found:
        other_cluster = vm_cluster(other)
        if other_cluster == cluster:
            others.append(other)
        else:
            log.warning(
                "SE VM '%s' is in cluster '%s', not '%s'; it can't be in " "this cluster's rule",
                other.name,
                getattr(other_cluster, "name", None),
                cluster.name,
            )
    for name in sorted(wanted - {other.name for other in found}):
        log.warning("SE '%s' (from the Avi API) has no VM in vCenter", name)
    return others + [vm]


def find_anti_affinity_rule(cluster, rule_name: str):
    """Return the cluster's anti-affinity rule with this name, or None."""
    return next(
        (
            r
            for r in cluster.configurationEx.rule
            if isinstance(r, vim.cluster.AntiAffinityRuleSpec) and r.name == rule_name
        ),
        None,
    )


def plan_rule_change(cluster, vm, rule_name: str, group_vms):
    """Work out the rule spec that puts the group's VMs in the rule.

    Returns (rule spec, description), or None if there's nothing to do.
    """
    existing = find_anti_affinity_rule(cluster, rule_name)
    if existing:
        in_rule = list(existing.vm)
        missing = [v for v in group_vms if v not in in_rule]
        if not missing:
            log.info(
                "All of the SE group's VMs in cluster '%s' are already in " "rule '%s'; nothing to do",
                cluster.name,
                rule_name,
            )
            return None
        info = vim.cluster.AntiAffinityRuleSpec(
            key=existing.key,
            name=rule_name,
            enabled=existing.enabled,
            vm=in_rule + missing,
        )
        vm_names = ", ".join(v.name for v in missing)
        return (
            vim.cluster.RuleSpec(operation="edit", info=info),
            f"Adding {vm_names} to existing rule '{rule_name}'",
        )
    if len(group_vms) < 2:
        log.info(
            "Rule '%s' doesn't exist and '%s' is the SE group's only SE "
            "VM in cluster '%s'; the rule will be created when the next "
            "SE is added",
            rule_name,
            vm.name,
            cluster.name,
        )
        return None
    info = vim.cluster.AntiAffinityRuleSpec(name=rule_name, enabled=True, userCreated=True, vm=group_vms)
    vm_names = ", ".join(v.name for v in group_vms)
    return (
        vim.cluster.RuleSpec(operation="add", info=info),
        f"Creating rule '{rule_name}' with {vm_names}",
    )


# Each argument is a separate input the caller already has; dry_run is
# keyword-only so it can't be passed by position by mistake.
def add_vm_to_anti_affinity_rule(  # pylint: disable=too-many-arguments
    content, cluster, vm, rule_name: str, se_names, *, dry_run: bool = False
) -> None:
    """Put all of the SE group's VMs in the named anti-affinity rule.

    Every VM in the cluster for an SE in the group (from the Avi API), and
    the new SE's VM, goes in the rule. VMs already in the rule aren't added
    again, and VMs in the rule are never removed. Creates the rule if it
    doesn't exist yet. Does nothing unless the SE group has at least two
    Service Engines.

    Args:
        se_names: Names of the SEs in the SE group, from the Avi API. The
            new SE counts even if Avi doesn't list it yet.
    """
    group_size = len(set(se_names) | {vm.name})
    if group_size < 2:
        log.info(
            "'%s' is the only SE in its SE group; not changing rule '%s'",
            vm.name,
            rule_name,
        )
        return
    log.info(
        "SE group has %d SEs, counting '%s'; updating rule '%s'",
        group_size,
        vm.name,
        rule_name,
    )

    group_vms = find_se_group_vms(content, cluster, vm, se_names)
    change = plan_rule_change(cluster, vm, rule_name, group_vms)
    if change is None:
        return
    rule_spec, action = change

    if dry_run:
        log.info("[dry run] %s on cluster '%s'", action, cluster.name)
        return

    log.info("%s on cluster '%s'", action, cluster.name)
    task = cluster.ReconfigureComputeResource_Task(vim.cluster.ConfigSpecEx(rulesSpec=[rule_spec]), modify=True)
    WaitForTask(task)
    log.info("Done")


def drop_avi_verify_warning(record: logging.LogRecord) -> bool:
    """Log filter: drop the Avi SDK's message about verify=False sessions."""
    return AVI_SDK_VERIFY_WARNING not in record.getMessage()


def quiet_ssl_warnings() -> None:
    """Stop SSL certificate verification warnings reaching the output.

    The controller API at DOCKER_GATEWAY is reached by IP address, so its
    certificate can't be verified. Without this, the Avi SDK logs and raises
    a warning for every session, and urllib3 warns on every request.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", message=rf"\s*\**\s*{AVI_SDK_VERIFY_WARNING}")
    logging.getLogger("avi.sdk.avi_api").addFilter(drop_avi_verify_warning)


def main(argv: list[str]) -> int:
    """Run the script.

    Args:
        argv (list): Arguments, without the program name.

    Returns:
        int: Exit status: 0 on success, 1 if the SE VM isn't in vCenter, 2 if
        no SE name, SE group or cloud name was given.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    quiet_ssl_warnings()
    args = parse_args(argv)

    se_vm_name, seg_name, cloud_name, seg_uuid = (None, None, None, None)
    if args.event:
        se_vm_name, seg_name, cloud_name, seg_uuid = parse_event(args.event)
    se_vm_name = args.se_vm_name or se_vm_name
    if args.service_engine_group:
        seg_name = args.service_engine_group
    if args.cloud_name:
        cloud_name = args.cloud_name
    if args.service_engine_group or args.cloud_name:
        # The alert's SE group UUID is for its own group, not this one.
        seg_uuid = None
    if not se_vm_name or not seg_name or not cloud_name:
        log.error(
            "No SE name/SE group/cloud name: pass the Avi alert JSON as the " "first argument, or use --event-file"
        )
        return 2

    vcenter, user, password = parse_vcenter_credentials(args)
    controller = args.controller_fqdn or get_controller_cluster_name(get_avi_session())
    rule_name = f"avi_se_antiaffinity_{controller}_{cloud_name}_{seg_name}"
    se_names = args.se_group_members
    if se_names is None:
        se_names = get_se_group_se_names(get_avi_session(), seg_name, cloud_name, seg_uuid)

    si = SmartConnect(
        host=vcenter,
        user=user,
        pwd=password,
        disableSslCertValidation=args.insecure or not VERIFY_VCENTER_CERT,
    )
    try:
        content = si.RetrieveContent()
        vm = find_vm(content, se_vm_name)
        if vm is None:
            log.error("SE VM '%s' not found in vCenter %s", se_vm_name, vcenter)
            return 1
        add_vm_to_anti_affinity_rule(
            content,
            get_cluster(vm),
            vm,
            rule_name,
            se_names,
            dry_run=args.dry_run,
        )
    finally:
        Disconnect(si)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

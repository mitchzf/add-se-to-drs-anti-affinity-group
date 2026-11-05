"""Unit tests for the credentials decryption in the ControlScript.

decrypt_credentials uses cryptography's PKCS#7 functions where they exist,
and the script's own decrypt_cms_fallback on older cryptography versions;
the tests run against both.
"""

# pytest fixtures are passed as arguments with the same names as the
# fixtures, and some tests need several of them.
# pylint: disable=missing-function-docstring,redefined-outer-name
# pylint: disable=too-many-arguments,too-many-positional-arguments

import json
import shutil

# Only runs openssl with fixed arguments.
import subprocess  # nosec B404
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from conftest import (
    CREDS,
    OID_AES128_CBC,
    OID_AES128_WRAP,
    OID_AES256_CBC,
    OID_AES256_GCM,
    OID_DATA,
    OID_ECDH_SHA256_KDF,
    OID_ENVELOPED_DATA,
    OID_RSAES_OAEP,
    der,
    der_int,
    ec_recipient,
    issuer_and_serial,
    make_cms,
    make_key_and_cert,
)


@pytest.fixture(params=["cryptography", "fallback"])
def decrypt_with(request, cs, monkeypatch):
    """Run a test with cryptography's PKCS#7 decryption, then without it.

    Without it (cryptography before 44, as on some Avi controllers),
    decrypt_credentials uses the script's own decrypt_cms_fallback.
    """
    if request.param == "fallback":
        monkeypatch.setattr(cs, "pkcs7", SimpleNamespace())
    return request.param


@pytest.mark.usefixtures("decrypt_with")
@pytest.mark.parametrize(
    "encoding",
    [
        serialization.Encoding.SMIME,
        serialization.Encoding.PEM,
        serialization.Encoding.DER,
    ],
)
def test_decrypt_credentials_formats(
    cs, key_and_cert, encrypt, creds_bytes, encoding
):
    encrypted = encrypt(creds_bytes, encoding)
    plain = cs.decrypt_credentials(encrypted, *key_and_cert)
    assert json.loads(plain) == CREDS


@pytest.mark.usefixtures("decrypt_with")
def test_decrypt_credentials_cms_pem_header(
    cs, key_and_cert, encrypt, creds_bytes
):
    """openssl cms -outform PEM writes BEGIN CMS headers; accept them."""
    pem = encrypt(creds_bytes, serialization.Encoding.PEM)
    cms_pem = pem.replace(b"BEGIN PKCS7", b"BEGIN CMS").replace(
        b"END PKCS7", b"END CMS"
    )
    assert json.loads(cs.decrypt_credentials(cms_pem, *key_and_cert)) == CREDS


@pytest.mark.usefixtures("decrypt_with")
@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl CLI not installed"
)
@pytest.mark.parametrize(
    "key_fixture, extra_args",
    [
        ("key_and_cert", []),
        ("key_and_cert", ["-outform", "PEM"]),
        ("key_and_cert", ["-outform", "DER"]),
        ("key_and_cert", ["-stream"]),
        ("ec_key_and_cert", []),
        ("ec_key_and_cert", ["-outform", "PEM"]),
        ("ec_key_and_cert", ["-outform", "DER"]),
        ("ec_key_and_cert", ["-stream"]),
        ("ec_key_and_cert", ["-keyid"]),
    ],
    ids=[
        "rsa-smime",
        "rsa-pem",
        "rsa-der",
        "rsa-smime-stream",
        "ec-smime",
        "ec-pem",
        "ec-der",
        "ec-smime-stream",
        "ec-keyid",
    ],
)
def test_decrypt_credentials_openssl_cms_command(
    cs, request, tmp_path, creds_bytes, key_fixture, extra_args
):
    """Files made with the documented openssl command decrypt correctly.

    With an RSA or an EC certificate (certbot makes EC ones by default).
    -stream makes openssl write BER with indefinite lengths; -keyid names
    the recipient by subject key identifier.
    """
    key_and_cert = request.getfixturevalue(key_fixture)
    (tmp_path / "credentials.json").write_bytes(creds_bytes)
    (tmp_path / "controlscript_cert.pem").write_bytes(
        key_and_cert[1].public_bytes(serialization.Encoding.PEM)
    )
    # Fixed arguments and no shell; the test is skipped if openssl is missing.
    subprocess.run(  # nosec B603 B607
        [
            "openssl",
            "cms",
            "-encrypt",
            "-in",
            "credentials.json",
            "-out",
            "credentials.json.enc",
            "-recip",
            "controlscript_cert.pem",
            "-aes256",
            *extra_args,
        ],
        cwd=tmp_path,
        check=True,
    )
    encrypted = (tmp_path / "credentials.json.enc").read_bytes()
    assert (
        json.loads(cs.decrypt_credentials(encrypted, *key_and_cert)) == CREDS
    )


def test_make_cms_output_is_valid(cs, key_and_cert, creds_bytes):
    """cryptography itself decrypts the test helper's hand-built CMS data."""
    cms = make_cms(creds_bytes, key_and_cert[1])
    assert json.loads(cs.decrypt_credentials(cms, *key_and_cert)) == CREDS


@pytest.mark.parametrize(
    "options",
    [
        {"indefinite": True},
        {"content_alg": OID_AES128_CBC, "content_key_size": 16},
        # A recipient type other than key transport is skipped.
        {"other_recipients": [der(0xA3, b"password recipient")]},
    ],
    ids=["ber-indefinite", "aes128", "other-recipient-type"],
)
def test_decrypt_cms_fallback_variants(cs, key_and_cert, creds_bytes, options):
    cms = make_cms(creds_bytes, key_and_cert[1], **options)
    assert json.loads(cs.decrypt_cms_fallback(cms, *key_and_cert)) == CREDS


def test_decrypt_cms_fallback_skips_other_recipients(
    cs, key_and_cert, other_key_and_cert, creds_bytes
):
    """Only the key encrypted to our certificate is used."""
    other_rid = issuer_and_serial(other_key_and_cert[1])
    other = der(0x30, der_int(0), other_rid, der(0x30), der(0x04, b"x"))
    cms = make_cms(creds_bytes, key_and_cert[1], other_recipients=[other])
    assert json.loads(cs.decrypt_cms_fallback(cms, *key_and_cert)) == CREDS


def test_decrypt_cms_fallback_subject_key_identifier(cs, creds_bytes):
    """openssl cms -keyid names the recipient by subject key identifier."""
    key, cert = make_key_and_cert(with_ski=True)
    ski = cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    cms = make_cms(creds_bytes, cert, rid=der(0x80, ski))
    assert json.loads(cs.decrypt_cms_fallback(cms, key, cert)) == CREDS


def test_decrypt_cms_fallback_wrong_certificate(
    cs, key_and_cert, other_key_and_cert, creds_bytes
):
    cms = make_cms(creds_bytes, other_key_and_cert[1])
    with pytest.raises(ValueError, match="wasn't encrypted to this cert"):
        cs.decrypt_cms_fallback(cms, *key_and_cert)


def test_decrypt_cms_fallback_ski_but_cert_has_none(
    cs, key_and_cert, creds_bytes
):
    cms = make_cms(creds_bytes, key_and_cert[1], rid=der(0x80, b"\x01" * 20))
    with pytest.raises(ValueError, match="wasn't encrypted to this cert"):
        cs.decrypt_cms_fallback(cms, *key_and_cert)


@pytest.mark.parametrize(
    "options, message",
    [
        ({"content_type": OID_DATA}, "isn't enveloped"),
        ({"rid": der(0x02, b"\x01")}, "Unsupported CMS recipient identifier"),
        ({"key_alg": OID_RSAES_OAEP}, "Unsupported CMS key encryption"),
        ({"content_alg": OID_AES256_GCM}, "Unsupported CMS content"),
    ],
    ids=["not-enveloped", "recipient-id", "rsa-oaep", "aes-gcm"],
)
def test_decrypt_cms_fallback_unsupported(
    cs, key_and_cert, creds_bytes, options, message
):
    cms = make_cms(creds_bytes, key_and_cert[1], **options)
    with pytest.raises(ValueError, match=message):
        cs.decrypt_cms_fallback(cms, *key_and_cert)


def test_decrypt_cms_fallback_content_key_size_mismatch(
    cs, key_and_cert, creds_bytes
):
    """An AES-256 label on a 128-bit key means the key didn't decrypt."""
    cms = make_cms(creds_bytes, key_and_cert[1], content_key_size=16)
    with pytest.raises(ValueError, match="Couldn't decrypt the CMS content"):
        cs.decrypt_cms_fallback(cms, *key_and_cert)


@pytest.mark.parametrize(
    "data, message",
    [
        (b"\x30", "Truncated"),
        (b"\x30\x05\x06\x01", "Truncated"),
        (b"\x30\x80\x06\x00", "Truncated"),  # no end-of-contents marker
        (b"\x1f\x01\x00", "multi-byte BER tag"),
        (b"\x30\x00", "Couldn't decrypt the credentials file"),
        (der(0x30, der(0x06, OID_ENVELOPED_DATA), der(0xA0, der(0x30))), ""),
    ],
    ids=[
        "short",
        "short-contents",
        "no-eoc",
        "multibyte-tag",
        "empty",
        "no-recipients",
    ],
)
def test_decrypt_cms_fallback_malformed(cs, key_and_cert, data, message):
    with pytest.raises(
        ValueError, match="Couldn't decrypt the credentials file"
    ) as exc:
        cs.decrypt_cms_fallback(data, *key_and_cert)
    assert message in str(exc.value)


def test_cms_to_der_smime_without_content(cs):
    smime = (
        b"MIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="b"\n\n--b--\n'
    )
    with pytest.raises(ValueError, match="S/MIME file has no encrypted"):
        cs.cms_to_der(smime)


# ---------------------------------------------------------------------------
# EC certificates (ECDH key agreement)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("decrypt_with")
def test_decrypt_credentials_ec_key(cs, ec_key_and_cert, creds_bytes):
    """EC keys always use the fallback; cryptography only supports RSA."""
    cms = make_cms(creds_bytes, ec_key_and_cert[1])
    assert json.loads(cs.decrypt_credentials(cms, *ec_key_and_cert)) == CREDS


@pytest.mark.parametrize(
    "ec_options",
    [
        {"ukm": b"user keying material"},
        # Long enough that the KDF input needs a long-form DER length.
        {"ukm": b"u" * 200},
        {"kdf_oid": OID_ECDH_SHA256_KDF, "kdf_hash": hashes.SHA256},
        {"wrap_oid": OID_AES128_WRAP, "kek_size": 16},
    ],
    ids=["ukm", "long-ukm", "sha256-kdf", "aes128-wrap"],
)
def test_decrypt_cms_fallback_ec_variants(
    cs, ec_key_and_cert, creds_bytes, ec_options
):
    cms = make_cms(creds_bytes, ec_key_and_cert[1], ec_options=ec_options)
    assert json.loads(cs.decrypt_cms_fallback(cms, *ec_key_and_cert)) == CREDS


def test_decrypt_cms_fallback_ec_subject_key_identifier(cs, creds_bytes):
    """openssl cms -keyid names an EC recipient by RecipientKeyIdentifier."""
    key, cert = make_key_and_cert(with_ski=True, ec_key=True)
    ski = cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    cms = make_cms(
        creds_bytes, cert, ec_options={"rid": der(0xA0, der(0x04, ski))}
    )
    assert json.loads(cs.decrypt_cms_fallback(cms, key, cert)) == CREDS


def test_decrypt_cms_fallback_mixed_recipients(
    cs, key_and_cert, ec_key_and_cert, creds_bytes
):
    """Each key only reads the recipient type it can decrypt.

    One file is encrypted to an RSA and an EC certificate, so each key
    skips the other's recipient.
    """
    rsa_cms = make_cms(
        creds_bytes,
        key_and_cert[1],
        other_recipients=[ec_recipient(ec_key_and_cert[1], b"\0" * 32)],
    )
    assert json.loads(cs.decrypt_cms_fallback(rsa_cms, *key_and_cert)) == (
        CREDS
    )
    ec_cms = make_cms(
        creds_bytes,
        ec_key_and_cert[1],
        other_recipients=[
            der(0x30, der_int(0), issuer_and_serial(key_and_cert[1]))
        ],
    )
    assert json.loads(cs.decrypt_cms_fallback(ec_cms, *ec_key_and_cert)) == (
        CREDS
    )


def test_decrypt_cms_fallback_ec_wrong_certificate(
    cs, ec_key_and_cert, creds_bytes
):
    other_key, other_cert = make_key_and_cert("other-ec", ec_key=True)
    cms = make_cms(creds_bytes, other_cert)
    with pytest.raises(ValueError, match="wasn't encrypted to this cert"):
        cs.decrypt_cms_fallback(cms, other_key, ec_key_and_cert[1])
    with pytest.raises(ValueError, match="wasn't encrypted to this cert"):
        cs.decrypt_cms_fallback(cms, *ec_key_and_cert)


@pytest.mark.parametrize(
    "ec_options, message",
    [
        (
            {"originator": der(0xA0, der(0x80, b"\x01" * 20))},
            "Unsupported CMS key agreement originator",
        ),
        ({"kdf_oid": OID_RSAES_OAEP}, "Unsupported CMS key agreement"),
        ({"wrap_oid": OID_AES256_CBC}, "Unsupported CMS key agreement"),
        # The file says SHA-1 but the key was derived with SHA-256, so the
        # derived key-encryption key is wrong.
        ({"kdf_hash": hashes.SHA256}, "didn't unwrap the content key"),
    ],
    ids=["originator-not-key", "kdf", "wrap", "wrong-kek"],
)
def test_decrypt_cms_fallback_ec_errors(
    cs, ec_key_and_cert, creds_bytes, ec_options, message
):
    cms = make_cms(creds_bytes, ec_key_and_cert[1], ec_options=ec_options)
    with pytest.raises(ValueError, match=message):
        cs.decrypt_cms_fallback(cms, *ec_key_and_cert)

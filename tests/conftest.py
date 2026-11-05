"""Shared fixtures for the ControlScript tests.

The script's file name has hyphens, so it's loaded with importlib rather than
imported.
Keys and certificates are generated per test session; nothing real is used.
"""

# Fixtures take other fixtures as arguments with the same name, and the fakes
# copy vCenter's method and attribute names (CreateContainerView, rootFolder),
# so these checks don't apply here.
# pylint: disable=redefined-outer-name,invalid-name,too-few-public-methods

import datetime
import importlib.util
import json
import os
import socket
from pathlib import Path

import pytest
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
from cryptography.x509.oid import NameOID
from pyVmomi import vim

PROJECT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_DIR / "avi-controlscript-se-antiaffinitygroup.py"

CREDS = {
    "vcenter": "vc.example.test",
    "username": "svc@vsphere.local",
    # Fake test value (B105). The nosec has no test ID because bandit
    # mis-attributes ID-specific nosec comments inside a multi-line dict.
    "password": "test-password",  # nosec
}


def load_script():
    """Load the script file as a module named ``controlscript``."""
    spec = importlib.util.spec_from_file_location("controlscript", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Can't load the script from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NetworkBlockedError(RuntimeError):
    """A test tried to open a network connection."""


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that tries to reach a real system over the network.

    vCenter (SmartConnect) and the Avi API must be mocked; if a mock is
    missing, the test fails here instead of connecting.
    """

    def blocked(*args, **kwargs):
        raise NetworkBlockedError(
            f"Test tried to open a network connection: {args[1:]} {kwargs}"
        )

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def cs():
    """A fresh copy of the script module for each test.

    Keeps patches from leaking between tests.
    """
    return load_script()


def make_key_and_cert(name="controlscript-test", with_ski=False, ec_key=False):
    """Make a throwaway key and matching self-signed certificate.

    The key is RSA, or EC P-256 (like certbot's default) with ``ec_key``.
    With ``with_ski``, the certificate has a subject key identifier.
    """
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    if ec_key:
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if with_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    return key, builder.sign(key, hashes.SHA256())


@pytest.fixture(scope="session")
def key_and_cert():
    """The key and certificate the test credentials are encrypted to."""
    return make_key_and_cert()


@pytest.fixture(scope="session")
def ec_key_and_cert():
    """An EC P-256 key and certificate, like the ones certbot makes."""
    return make_key_and_cert("controlscript-ec", with_ski=True, ec_key=True)


@pytest.fixture(scope="session")
def other_key_and_cert():
    """A second key and certificate, for files encrypted to someone else."""
    return make_key_and_cert("someone-else")


@pytest.fixture(scope="session")
def key_pem(key_and_cert):
    """The test private key as unencrypted PEM."""
    return key_and_cert[0].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def cert_pem(key_and_cert):
    """The test certificate as PEM."""
    return key_and_cert[1].public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def creds_bytes():
    """The test credentials as JSON bytes."""
    return json.dumps(CREDS).encode()


@pytest.fixture(scope="session")
def encrypt(key_and_cert):
    """Encrypt bytes to the test certificate with AES-256.

    The result is in the given output encoding (S/MIME, PEM or DER).
    """

    def _encrypt(data: bytes, encoding: serialization.Encoding) -> bytes:
        options = (
            [pkcs7.PKCS7Options.Binary]
            if encoding != serialization.Encoding.SMIME
            else []
        )
        return (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(data)
            .set_content_encryption_algorithm(algorithms.AES256)
            .add_recipient(key_and_cert[1])
            .encrypt(encoding, options)
        )

    return _encrypt


# DER contents of the object identifiers make_cms writes.
OID_DATA = bytes.fromhex("2a864886f70d010701")  # id-data
OID_ENVELOPED_DATA = bytes.fromhex("2a864886f70d010703")
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")
OID_RSAES_OAEP = bytes.fromhex("2a864886f70d010107")
OID_AES128_CBC = bytes.fromhex("608648016503040102")
OID_AES256_CBC = bytes.fromhex("60864801650304012a")
OID_AES256_GCM = bytes.fromhex("60864801650304012e")
OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")
OID_ECDH_SHA1_KDF = bytes.fromhex("2b81051086483f0002")  # openssl's default
OID_ECDH_SHA256_KDF = bytes.fromhex("2b8104010b01")
OID_AES128_WRAP = bytes.fromhex("608648016503040105")
OID_AES256_WRAP = bytes.fromhex("60864801650304012d")


def der(tag: int, *parts: bytes, indefinite: bool = False) -> bytes:
    """Encode one DER element, or a BER indefinite-length one."""
    body = b"".join(parts)
    if indefinite:
        return bytes([tag, 0x80]) + body + b"\0\0"
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def der_int(value: int) -> bytes:
    """Encode an INTEGER."""
    return der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def issuer_and_serial(cert) -> bytes:
    """A recipient identifier naming the certificate by issuer and serial."""
    return der(0x30, cert.issuer.public_bytes(), der_int(cert.serial_number))


# One keyword per part of the CMS structure a test may want to change.
# One keyword per part of the recipient a test may want to change.
def ec_recipient(  # pylint: disable=too-many-arguments,too-many-locals
    cert,
    content_key: bytes,
    *,
    kdf_oid=OID_ECDH_SHA1_KDF,
    kdf_hash=hashes.SHA1,
    wrap_oid=OID_AES256_WRAP,
    kek_size=32,
    ukm=None,
    originator=None,
    rid=None,
) -> bytes:
    """Build a KeyAgreeRecipientInfo (ECDH, RFC 5753) by hand.

    This is what openssl cms -encrypt writes for an EC certificate.
    ``kdf_oid``/``wrap_oid`` are what the file declares; ``kdf_hash`` and
    ``kek_size`` are what's actually used, so tests can make them differ.
    """
    one_off = ec.generate_private_key(cert.public_key().curve)
    shared = one_off.exchange(ec.ECDH(), cert.public_key())
    wrap_alg = der(0x30, der(0x06, wrap_oid))
    shared_info = der(
        0x30,
        wrap_alg,
        der(0xA0, der(0x04, ukm)) if ukm else b"",
        der(0xA2, der(0x04, (kek_size * 8).to_bytes(4, "big"))),
    )
    kek = X963KDF(kdf_hash(), kek_size, shared_info).derive(shared)
    point = one_off.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    if originator is None:
        originator = der(
            0xA0,
            der(
                0xA1,
                der(0x30, der(0x06, OID_EC_PUBLIC_KEY)),
                der(0x03, b"\0" + point),
            ),
        )
    return der(
        0xA1,
        der_int(3),
        originator,
        der(0xA1, der(0x04, ukm)) if ukm else b"",
        der(0x30, der(0x06, kdf_oid), wrap_alg),
        der(
            0x30,
            der(
                0x30,
                rid if rid is not None else issuer_and_serial(cert),
                der(0x04, keywrap.aes_key_wrap(kek, content_key)),
            ),
        ),
    )


def make_cms(  # pylint: disable=too-many-arguments,too-many-locals
    data: bytes,
    cert,
    *,
    rid=None,
    key_alg=OID_RSA_ENCRYPTION,
    content_alg=OID_AES256_CBC,
    content_key_size=32,
    other_recipients=(),
    content_type=OID_ENVELOPED_DATA,
    indefinite=False,
    ec_options=None,
) -> bytes:
    """Build CMS enveloped data by hand, the way openssl cms -encrypt does.

    Each keyword changes one part, so tests can reach every check in the
    script's fallback decryption. ``indefinite`` writes BER with
    indefinite lengths and a chunked encrypted content, like openssl's
    -stream option. For an EC certificate, the recipient is built by
    ec_recipient, with ``ec_options`` as its keywords.
    """
    content_key = os.urandom(content_key_size)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    if isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        recipient = ec_recipient(cert, content_key, **(ec_options or {}))
    else:
        recipient = der(
            0x30,
            der_int(0),
            rid if rid is not None else issuer_and_serial(cert),
            der(0x30, der(0x06, key_alg), der(0x05)),
            der(
                0x04,
                cert.public_key().encrypt(content_key, rsa_padding.PKCS1v15()),
            ),
        )
    if indefinite:
        encrypted_content = der(
            0xA0,
            der(0x04, ciphertext[:16]),
            der(0x04, ciphertext[16:]),
            indefinite=True,
        )
    else:
        encrypted_content = der(0x80, ciphertext)
    enveloped = der(
        0x30,
        der_int(0),
        der(0x31, *other_recipients, recipient),
        der(
            0x30,
            der(0x06, OID_DATA),
            der(0x30, der(0x06, content_alg), der(0x04, iv)),
            encrypted_content,
        ),
        indefinite=indefinite,
    )
    return der(
        0x30,
        der(0x06, content_type),
        der(0xA0, enveloped, indefinite=indefinite),
        indefinite=indefinite,
    )


class FakeVM(vim.VirtualMachine):
    """A real vim.VirtualMachine with a local name and runtime.

    Being a real VirtualMachine means pyVmomi's type checks pass.
    """

    def __init__(self, moid, name, host=None):
        super().__init__(moid)
        self.__dict__["_fake_name"] = name
        self.__dict__["_fake_runtime"] = type("Runtime", (), {"host": host})()

    @property
    def name(self):
        return self.__dict__["_fake_name"]

    @property
    def runtime(self):
        return self.__dict__["_fake_runtime"]


class FakeCluster(vim.ClusterComputeResource):
    """A real vim.ClusterComputeResource with local rules.

    ReconfigureComputeResource_Task records its arguments instead of
    calling vCenter.
    """

    def __init__(self, moid, name="cl1", rules=()):
        super().__init__(moid)
        self.__dict__["_fake_name"] = name
        self.__dict__["_fake_config"] = type(
            "ConfigurationEx", (), {"rule": list(rules)}
        )()
        self.__dict__["reconfigure_calls"] = []

    @property
    def name(self):
        """The cluster's name."""
        return self.__dict__["_fake_name"]

    @property
    def configurationEx(self):
        """The cluster's configuration; only ``rule`` is set."""
        return self.__dict__["_fake_config"]

    def ReconfigureComputeResource_Task(self, spec, modify):
        """Record the change and return a fake task."""
        self.__dict__["reconfigure_calls"].append((spec, modify))
        return "task-1"


class FakeView:
    """Stands in for a vCenter container view."""

    def __init__(self, objects):
        self.view = list(objects)
        self.destroyed = False

    def Destroy(self):
        """Record that the view was destroyed."""
        self.destroyed = True


class FakeContent:
    """Stands in for ServiceInstance content.

    Container views list the given VMs.
    """

    def __init__(self, all_vms=(), cluster_vms=None):
        self.rootFolder = object()
        self.all_vms = list(all_vms)
        self.cluster_vms = list(
            cluster_vms if cluster_vms is not None else all_vms
        )
        self.views = []
        self.viewManager = self

    def CreateContainerView(self, container, types, recursive):
        """Return a view of all VMs, or of the cluster's VMs."""
        assert types == [vim.VirtualMachine] and recursive is True
        view = FakeView(
            self.all_vms if container is self.rootFolder else self.cluster_vms
        )
        self.views.append(view)
        return view


class FakeResponse:
    """Stands in for a requests response from the Avi API."""

    def __init__(
        self,
        content=b"",
        status_code=200,
        content_type="application/octet-stream",
    ):
        self.content = content
        self.status_code = status_code
        self.text = content.decode(errors="replace")
        self.headers = {"Content-Type": content_type}

    def json(self):
        """Parse the body as JSON."""
        return json.loads(self.content)


class FakeAviSession:
    """Records calls and serves canned objects, like avi.sdk ApiSession."""

    def __init__(
        self, objects=None, download=None, lists=None, responses=None
    ):
        self.objects = objects or {}
        self.download = download or FakeResponse()
        self.lists = lists or {}
        self.responses = responses or {}
        self.calls = []

    def get_object_by_name(self, obj_type, name, params=None):
        """Return the canned object for this type and name, or None."""
        self.calls.append(("get_object_by_name", obj_type, name, params))
        return self.objects.get((obj_type, name))

    def get(self, path, params=None):
        """Return the canned response for this path, or the download."""
        self.calls.append(("get", path, params))
        return self.responses.get(path, self.download)

    def get_objects_iter(self, obj_type, params=None):
        """Yield the canned objects listed for this type."""
        self.calls.append(("get_objects_iter", obj_type, params))
        yield from self.lists.get(obj_type, [])

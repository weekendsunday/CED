"""本地 CA + 按域名动态签发叶子证书 —— 自动捕获的 HTTPS 明文化（可选能力）。

依赖与降级口径
--------------
* 装了 ``cryptography`` → 自动生成/加载本地 CA，对 CONNECT 隧道做 MITM，
  解密出的明文请求进同一条差分管线。
* 没装 → MITM 不可用，代理保持 CONNECT 隧道直通（一条 HTTPS 都不拆，
  如实计数）—— **零依赖底线不动**。
* CA 私钥只存本机用户目录（``~/.ced/mitm/``），绝不入仓库、绝不上传。

合规：MITM 解密的是**本机用户自己浏览器**的流量；界面与启动日志都会写明
"本机中间人、数据不出本机"。证书固定（pinning）的客户端会拒绝本地 CA ——
这类握手失败被如实计数（``tls_failed``），绝不伪装成捕获成功。
"""
from __future__ import annotations

import ssl
import threading
import datetime
from pathlib import Path

CA_DIR = Path.home() / ".ced" / "mitm"
CA_CERT = CA_DIR / "ca.crt"
CA_KEY = CA_DIR / "ca.key.pem"
HOSTS_DIR = CA_DIR / "hosts"
#: 证书有效期（天）—— CA 长一些，叶子短一些
CA_DAYS = 3650
LEAF_DAYS = 365


def mitm_available() -> bool:
    """本机是否具备 MITM 能力（只看可选依赖，不生成任何文件）。"""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def ca_cert_path() -> Path | None:
    """已存在的 CA 证书路径；没生成过返回 None。"""
    return CA_CERT if CA_CERT.is_file() else None


def ensure_ca() -> Path:
    """生成（或加载）本地 CA。返回 CA 证书路径。抛 ImportError = 无可选依赖。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_CERT.is_file() and CA_KEY.is_file():
        return CA_CERT

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CED Local Capture CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    CA_KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), )
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CA_CERT


def leaf_context(host: str, _cache: dict = {}, _lock: threading.Lock = threading.Lock()) -> ssl.SSLContext:
    """给定域名，返回 server_side 的 SSLContext（叶子证书按域名签发并缓存）。

    主线程之外的捕获线程并发调用 —— 用锁保护签发缓存。
    """
    ctx = _cache.get(host)
    if ctx is not None:
        return ctx
    with _lock:
        ctx = _cache.get(host)
        if ctx is not None:
            return ctx
        _ensure_leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(HOSTS_DIR / f"{host}.chain.crt",
                            HOSTS_DIR / f"{host}.key.pem")
        _cache[host] = ctx
        return ctx


def upstream_context() -> ssl.SSLContext:
    """连真实站点用的 client 侧 context：不校验证书（我们只做观测，不做防护）。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _ensure_leaf(host: str) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HOSTS_DIR.mkdir(parents=True, exist_ok=True)
    cert_path = HOSTS_DIR / f"{host}.crt"
    key_path = HOSTS_DIR / f"{host}.key.pem"
    chain_path = HOSTS_DIR / f"{host}.chain.crt"
    if chain_path.is_file() and key_path.is_file():
        return

    ca_key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # CN 上限 64 字符（x509.NameAttribute 硬限制）；真实 CDN 域名有更长的 ——
    # CN 只是展示名，域名校验走 SAN（DNSName 无此限制），超长就截断。
    common_name = host[:64]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    san_names = [x509.DNSName(host)]
    try:
        import ipaddress
        san_names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        pass                        # 不是 IP 字面量，DNS SAN 即可
    san = x509.SubjectAlternativeName(san_names)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=LEAF_DAYS))
            .add_extension(san, critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=True, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # 服务端要发「叶子 + CA」整链：Windows schannel 对只发叶子的自签链会报
    # 0x80096004（签名无法验证），OpenSSL 客户端则无所谓 —— 发整链两边都过。
    chain_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                           + CA_CERT.read_bytes())


def install_hint(ca: Path) -> str:
    """把 CA 装进信任库的人话指引（按平台）。"""
    import sys
    if sys.platform == "win32":
        return (f"信任本地 CA（管理员或用户级任选其一）：\n"
                f"  certutil -user -addstore Root \"{ca}\"\n"
                f"或双击 {ca} → 安装证书 → 当前用户 → 受信任的根证书颁发机构。\n"
                f"Firefox 另行导入：设置 → 隐私与安全 → 证书 → 查看证书 → 导入。")
    if sys.platform == "darwin":
        return (f"信任本地 CA：\n"
                f"  sudo security add-trusted-cert -d -r trustRoot "
                f"-k /Library/Keychains/System.keychain \"{ca}\"")
    return (f"信任本地 CA：\n"
            f"  cp {ca} /usr/local/share/ca-certificates/ced-capture.crt"
            f" && sudo update-ca-certificates")

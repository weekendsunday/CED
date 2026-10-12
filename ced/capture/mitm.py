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
#: **自己生成** CA 时用的通用名。撤销信任、在钥匙串里找它都按证书里实际的 CN 走
#: （导入别人的 CA 时那个名字不是这个，见 :func:`ca_common_name`）。
CA_COMMON_NAME = "CED Local Capture CA"
#: 证书有效期（天）—— CA 长一些，叶子短一些
CA_DAYS = 3650
LEAF_DAYS = 365

#: 已签发的叶子证书按域名缓存 SSLContext —— TLS 握手在每个连接上都要用，
#: 不能每次都重新签发。清理由 :func:`purge_leaves` 一并清掉（换了 CA 之后
#: 旧上下文里的链已经不作数了）。
_LEAF_CACHE: dict[str, ssl.SSLContext] = {}
_LEAF_LOCK = threading.Lock()


def mitm_available() -> bool:
    """本机是否具备 MITM 能力（只看可选依赖，不生成任何文件）。"""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def _tighten(path: Path) -> None:
    """把目录收到只有本人能进 —— 里面躺的是这张 CA 的私钥。"""
    try:
        path.chmod(0o700)
    except OSError:
        pass          # 网盘 / 挂载卷改不了权限，不因为这一步中断捕获


def _write_private(path: Path, data: bytes) -> None:
    """写私钥，顺手收到 600。

    umask 通常是 022，不显式收紧就是 644 —— 同一台机器上任何账户都能读，
    等于把"本机中间人"的能力交出去。
    """
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def ca_cert_path() -> Path | None:
    """已存在的 CA 证书路径；没生成过返回 None。"""
    return CA_CERT if CA_CERT.is_file() else None


def ca_common_name() -> str:
    """本机这张 CA 的 CN。撤销信任、在钥匙串 / 证书库里找它都按这个名字走。

    一律**从证书本身读**：导入别人的 CA 时它多半不叫 CED Local Capture CA，
    写死常量会让"已信任/未信任"和"撤销"都指错东西。
    """
    if CA_CERT.is_file():
        try:
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
            for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
                if str(attr.value):
                    return str(attr.value)
        except Exception:            # noqa: BLE001 —— 读不出来就退回默认名，不在这里报错
            pass
    return CA_COMMON_NAME


def count_leaves() -> int:
    """已经签发过证书的域名数（只看文件，不需要可选依赖）。"""
    if not HOSTS_DIR.is_dir():
        return 0
    return len([p for p in HOSTS_DIR.iterdir()
                if p.name.endswith(".crt") and not p.name.endswith(".chain.crt")])


def purge_leaves() -> dict:
    """清掉已签发的叶子证书：落盘文件 + 内存里那份 SSLContext 缓存。

    两处都要清。只删文件的话，缓存里的上下文还带着旧链，握手持续用旧证书 ——
    看起来"清了个寂寞"。清完不影响捕获：下一个请求会重新签一张。
    """
    domains = count_leaves()
    removed = 0
    if HOSTS_DIR.is_dir():
        for item in sorted(HOSTS_DIR.iterdir()):
            if item.is_file():
                item.unlink()
                removed += 1
    with _LEAF_LOCK:
        _LEAF_CACHE.clear()
    return {"domains": domains, "files": removed, "dir": str(HOSTS_DIR)}


def ensure_ca() -> Path:
    """生成（或加载）本地 CA。返回 CA 证书路径。抛 ImportError = 无可选依赖。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CA_DIR.mkdir(parents=True, exist_ok=True)
    _tighten(CA_DIR)
    if CA_CERT.is_file() and CA_KEY.is_file():
        return CA_CERT

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
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
    _write_private(CA_KEY, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CA_CERT


def leaf_context(host: str) -> ssl.SSLContext:
    """给定域名，返回 server_side 的 SSLContext（叶子证书按域名签发并缓存）。

    主线程之外的捕获线程并发调用 —— 用锁保护签发缓存。
    """
    ctx = _LEAF_CACHE.get(host)
    if ctx is not None:
        return ctx
    with _LEAF_LOCK:
        ctx = _LEAF_CACHE.get(host)
        if ctx is not None:
            return ctx
        _ensure_leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(HOSTS_DIR / f"{host}.chain.crt",
                            HOSTS_DIR / f"{host}.key.pem")
        _LEAF_CACHE[host] = ctx
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
    _tighten(HOSTS_DIR)
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
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # 服务端要发「叶子 + CA」整链：Windows schannel 对只发叶子的自签链会报
    # 0x80096004（签名无法验证），OpenSSL 客户端则无所谓 —— 发整链两边都过。
    chain_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                           + CA_CERT.read_bytes())


# ------------------------------------------------------------------ 导入别人的 CA


def _pw(password: str | None) -> bytes | None:
    return password.encode("utf-8") if password else None


def _load_pair(blob: bytes, key_blob: bytes | None, password: str | None):
    """从上传的文件里找出（证书, 私钥），并说清是按哪种形态认出来的。

    两种常见形态都认：PEM（证书与私钥可以分两份，也可以挤在同一份里）与
    PKCS#12（.p12/.pfx —— 单位 / 团队分发 CA 时最常见的形态）。
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    if b"-----BEGIN CERTIFICATE-----" in blob:
        cert = x509.load_pem_x509_certificate(blob)
        if key_blob is None and b"PRIVATE KEY-----" in blob:
            key_blob = blob              # 常见导出：证书与私钥就写在同一份 PEM 里
        if key_blob is None:
            raise ValueError("只给了证书，没有私钥 —— 解密要用它签叶子证书："
                             "请把私钥一起选上（或在同一个文件里）")
        if b"PRIVATE KEY-----" not in key_blob:
            raise ValueError("私钥文件里没有 PEM 私钥（-----BEGIN ... PRIVATE KEY-----）")
        try:
            key = serialization.load_pem_private_key(key_blob, password=_pw(password))
        except (ValueError, TypeError) as exc:
            # 最常见的一种：私钥带口令而口令那一栏空着 —— 顺手把话说到位
            raise ValueError(f"私钥读不出来：{exc}"
                             f"（私钥加了口令的话，把口令填在「口令」一栏）") from exc
        return cert, key, "pem"

    from cryptography.hazmat.primitives.serialization import pkcs12
    try:
        key, cert, _chain = pkcs12.load_key_and_certificates(blob, _pw(password))
    except Exception as exc:             # noqa: BLE001 —— 底层原因原样带上，别让人猜
        raise ValueError(
            f"这个文件既不是 PEM 也不是能解开的 PKCS#12（{type(exc).__name__}：{exc}）——"
            f"若是 .p12/.pfx 请确认口令；也可以先转成 PEM："
            f"openssl pkcs12 -nodes -in ca.p12 -out ca.pem") from exc
    if key is None or cert is None:
        raise ValueError("这份 PKCS#12 里没有私钥或没有证书 —— 两样都要有")
    return cert, key, "pkcs12"


def _check_ca_pair(cert, key) -> None:
    """三件事：它是 CA、它有签发权、私钥与证书是同一对。缺一条当场拒。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("这张证书没写 BasicConstraints，判断不了它是不是 CA") from exc
    if not basic.ca:
        raise ValueError("这张不是 CA 证书（BasicConstraints CA:FALSE）—— 解密要用它"
                         "签发每个域名的叶子证书，请给根 CA 或中间 CA")
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        raise ValueError("这张 CA 证书没有 keyCertSign 权限，签不了叶子证书")
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    if (key.public_key().public_bytes(der, pub)
            != cert.public_key().public_bytes(der, pub)):
        raise ValueError("私钥与证书不是一对（公钥对不上）—— 这一对签出来的叶子没人认，"
                         "请换正确的一对")


def import_ca(blob: bytes, key_blob: bytes | None = None, *,
              password: str | None = None, replace: bool = False) -> dict:
    """导入一张**带私钥的 CA**，之后就由它签发叶子证书。

    给"团队 / 单位已经有一张被授权的 CA"这种场景用：一张 CA 大家共用，不必每人
    各生成一张（信任仍然**是每台机器各自**的事：导入完本机还得信任它一次）。

    为什么私钥是必须的：所谓解密 HTTPS，就是用这张 CA 现场签一张叶子证书递给客户端。
    只有证书没有私钥 = 签不出东西，那种情况本工具只能退回隧道直通并如实记录。

    换 CA 会连带清掉已签发的叶子证书：那些叶子是**旧 CA** 签的，留着只会让下次
    握手拿旧链、照样失败。

    出错一律抛 ``ValueError``，消息是给人看的（缺私钥 / 不是 CA / 不是一对 / 要确认替换）。
    """
    from cryptography.hazmat.primitives import serialization

    if not mitm_available():
        raise ValueError("本解释器缺可选依赖 cryptography，导入的 CA 也用不了："
                         "先 pip install cryptography 再重启界面")
    cert, key, fmt = _load_pair(blob, key_blob, password)
    _check_ca_pair(cert, key)

    existing = CA_CERT.is_file() and CA_KEY.is_file()
    if existing and not replace:
        raise ValueError(f"本机已经有一张 CA（{ca_common_name()}）—— "
                         f"导入会替换它，需要显式确认替换")

    CA_DIR.mkdir(parents=True, exist_ok=True)
    _tighten(CA_DIR)
    # 私钥先落，证书后落：中途出岔子也只留下"半个"，而所有判断都以证书为准
    _write_private(CA_KEY, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    purged = purge_leaves()
    return {"ok": True, "format": fmt, "ca": str(CA_CERT),
            "subject": cert.subject.rfc4514_string(), "cn": ca_common_name(),
            "replaced": existing, "domains": purged["domains"],
            "files": purged["files"]}


def install_hint(ca: Path) -> str:
    """把 CA 装进信任库的人话指引（按平台）。"""
    import sys
    if sys.platform == "win32":
        return (f"信任本地 CA（管理员或用户级任选其一）：\n"
                f"  certutil -user -addstore Root \"{ca}\"\n"
                f"或双击 {ca} → 安装证书 → 当前用户 → 受信任的根证书颁发机构。\n"
                f"Firefox 另行导入：设置 → 隐私与安全 → 证书 → 查看证书 → 导入。")
    if sys.platform == "darwin":
        return (f"信任本地 CA（不必 sudo）：\n"
                f"  security add-trusted-cert -r trustRoot -p ssl "
                f"-k ~/Library/Keychains/login.keychain-db \"{ca}\"\n"
                f"或双击 {ca} → 钥匙串访问里拖进「登录」→ 双击证书 → 信任 → SSL 始终信任。\n"
                f"（走「登录」而不是「系统」：这一步不需要管理员密码，界面上的状态也认得出来）\n"
                f"Firefox 另行导入：设置 → 隐私与安全 → 证书 → 查看证书 → 导入。")
    return (f"信任本地 CA：\n"
            f"  cp {ca} /usr/local/share/ca-certificates/ced-capture.crt"
            f" && sudo update-ca-certificates")

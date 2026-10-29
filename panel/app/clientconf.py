"""QR-коды и имена файлов конфигов клиентов TrustTunnel (deep link tt://? и TOML для CLI-клиента)."""
from __future__ import annotations

import io

import qrcode
import qrcode.image.svg


def qr_svg(text: str) -> bytes:
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, error_correction=qrcode.constants.ERROR_CORRECT_L,
                      box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue()


def qr_png(text: str) -> bytes:
    """QR картинкой — для Telegram и почты (SVG там не показывается)."""
    img = qrcode.make(text, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=3)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def file_name(name: str, username: str) -> str:
    """Имя файла .toml: имя клиента латиницей/цифрами, иначе по логину TrustTunnel."""
    keep = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "-_") else "_" for ch in name).strip("_")[:40]
    return f"{keep or 'tt-' + username}.toml"

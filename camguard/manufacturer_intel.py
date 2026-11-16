"""Conservative manufacturer aliases and CCTV product normalization.

Normalization is exact-alias based. Unknown values are preserved rather than
fuzzy-matched, and callers should retain the original vendor/product strings
as evidence alongside normalized values.
"""
from __future__ import annotations

import re
from typing import Any

def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


# Canonical names and aliases are deliberately explicit. Avoid broad aliases
# such as "Samsung" that could incorrectly identify unrelated products.
_MANUFACTURERS: dict[str, tuple[str, ...]] = {
    "Hikvision": (
        "Hikvision",
        "Hikvision Digital Technology",
        "Hangzhou Hikvision Digital Technology",
        "Hangzhou Hikvision Digital Technology Co., Ltd.",
        "Hikvision Digital Technology Co., Ltd.",
    ),
    "Dahua": (
        "Dahua",
        "Dahua Technology",
        "Zhejiang Dahua Technology",
        "Zhejiang Dahua Technology Co., Ltd.",
        "Dahua Technology Co., Ltd.",
    ),
    "Axis Communications": (
        "Axis",
        "Axis Communications",
        "Axis Communications AB",
    ),
    "Hanwha Vision": (
        "Hanwha",
        "Hanwha Vision",
        "Hanwha Vision Co., Ltd.",
        "Hanwha Techwin",
        "Hanwha Techwin Co., Ltd.",
    ),
    "Uniview": (
        "Uniview",
        "UNV",
        "Zhejiang Uniview Technologies",
        "Zhejiang Uniview Technologies Co., Ltd.",
    ),
    "Bosch Security Systems": (
        "Bosch Security Systems",
        "Bosch Building Technologies",
        "Bosch Sicherheitssysteme GmbH",
    ),
}

_MANUFACTURER_LOOKUP = {
    _key(alias): canonical
    for canonical, aliases in _MANUFACTURERS.items()
    for alias in aliases
}

# Only exact, generic product-family aliases are normalized. Model identifiers
# and vendor-specific product names are left intact.
_PRODUCT_ALIASES = {
    "nvr": "NVR",
    "network video recorder": "NVR",
    "network video recorders": "NVR",
    "ip camera": "IP Camera",
    "ip cameras": "IP Camera",
    "internet protocol camera": "IP Camera",
    "internet protocol cameras": "IP Camera",
    "network camera": "IP Camera",
    "network cameras": "IP Camera",
    "dvr": "DVR",
    "digital video recorder": "DVR",
    "digital video recorders": "DVR",
    "video management system": "VMS",
    "video management software": "VMS",
}
_PRODUCT_LOOKUP = {_key(alias): canonical for alias, canonical in _PRODUCT_ALIASES.items()}


def normalize_manufacturer(value: str | None) -> str | None:
    """Return a canonical supported manufacturer, or None for unknown values."""
    if not isinstance(value, str) or not value.strip():
        return None
    return _MANUFACTURER_LOOKUP.get(_key(value.strip()))


def normalize_product(vendor: str | None, product: str | None) -> str | None:
    """Normalize an exact generic product-family alias; preserve unknown names."""
    if not isinstance(product, str) or not product.strip():
        return None
    raw = product.strip()
    return _PRODUCT_LOOKUP.get(_key(raw), raw)


def normalize_device_identity(vendor: str | None, product: str | None) -> dict[str, Any]:
    """Return raw and normalized labels without discarding source evidence."""
    raw_vendor = vendor.strip() if isinstance(vendor, str) else None
    raw_product = product.strip() if isinstance(product, str) else None
    canonical_vendor = normalize_manufacturer(raw_vendor)
    return {
        "vendor_raw": raw_vendor,
        "vendor_normalized": canonical_vendor or raw_vendor,
        "manufacturer_supported": canonical_vendor is not None,
        "product_raw": raw_product,
        "product_normalized": normalize_product(canonical_vendor, raw_product),
        "normalization": "exact_alias",
    }


def supported_manufacturers() -> list[dict[str, Any]]:
    """Return a stable, JSON-serializable catalogue for CLI/help/report use."""
    return [
        {"canonical_name": canonical, "aliases": list(aliases)}
        for canonical, aliases in sorted(_MANUFACTURERS.items())
    ]

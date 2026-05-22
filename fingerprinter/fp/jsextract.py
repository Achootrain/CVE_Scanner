"""Compatibility shim -- real implementation lives in ``urlcrawl/``.

All URL/path discovery logic moved to the top-level ``urlcrawl`` package
(peer of ``fetchlib``) so the fp scanner and the lab back-test consume one
independent module. This file re-exports the public surface so existing
relative imports inside ``fp/`` (``from .jsextract import ...``,
``from . import jsextract as jsextract_mod``) keep working unchanged.

New callers should import from ``urlcrawl`` directly::

    from urlcrawl import extract_paths, extract_html_link_urls
"""

from urlcrawl import (  # noqa: F401
    ExtractedPath,
    HTML_LINK_URL_RE,
    looks_like_html,
    extract_html_link_urls,
    extract_inline_scripts,
    extract_paths,
    extract_paths_from_html,
)

__all__ = [
    "ExtractedPath",
    "HTML_LINK_URL_RE",
    "looks_like_html",
    "extract_html_link_urls",
    "extract_inline_scripts",
    "extract_paths",
    "extract_paths_from_html",
]

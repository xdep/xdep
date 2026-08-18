"""Generate the crawlable contact pages that seed an ``owned_web`` channel.

These are plain static pages for a domain the operator already owns. Their only
trick is being easy for a harvesting bot to parse: the number and address sit in
the text, in a ``tel:``/``mailto:`` link, and in schema.org microdata, and
``robots.txt`` invites crawlers instead of blocking them.

The pages describe the line honestly. A generated page never impersonates a real
company, and it carries a visible monitoring notice — that notice is what makes
the whole setup something the operator can point at afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

NOTICE = "This line is monitored and calls may be recorded for security research."


@dataclass(frozen=True)
class Listing:
    """One published contact point, matching one registered channel."""

    slug: str
    display_name: str
    phone: str
    email: str
    blurb: str = "Enquiries welcome. Leave a message and someone will get back to you."
    locality: str | None = None
    notice: str = NOTICE

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.slug):
            raise ValueError(f"slug must be url-safe lowercase: {self.slug!r}")
        if not self.phone.startswith("+"):
            raise ValueError("phone must be in E.164 form, e.g. +15550001111")


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} — Contact</title>
<meta name="description" content="Contact details for {name}.">
<meta name="robots" content="index, follow">
</head>
<body>
<main itemscope itemtype="https://schema.org/Organization">
  <h1 itemprop="name">{name}</h1>
  <p>{blurb}</p>
  <ul>
    <li>Phone: <a href="tel:{phone}" itemprop="telephone">{phone_display}</a></li>
    <li>Email: <a href="mailto:{email}" itemprop="email">{email}</a></li>
{locality}  </ul>
  <p><small>{notice}</small></p>
</main>
</body>
</html>
"""


def render(listing: Listing) -> str:
    locality = ""
    if listing.locality:
        locality = (
            "    <li>Area served: "
            f"<span itemprop=\"areaServed\">{escape(listing.locality)}</span></li>\n"
        )
    return _PAGE.format(
        name=escape(listing.display_name),
        blurb=escape(listing.blurb),
        phone=escape(listing.phone),
        phone_display=escape(_pretty_phone(listing.phone)),
        email=escape(listing.email),
        locality=locality,
        notice=escape(listing.notice),
    )


def _pretty_phone(e164: str) -> str:
    digits = e164.lstrip("+")
    if len(digits) == 11 and digits.startswith("1"):
        return f"({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    return e164


def render_index(listings: list[Listing], site_name: str) -> str:
    items = "\n".join(
        f'    <li><a href="/{escape(l.slug)}/">{escape(l.display_name)}</a></li>'
        for l in listings
    )
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{escape(site_name)}</title>\n<meta name=\"robots\" content=\"index, follow\">\n"
        f"</head>\n<body>\n  <h1>{escape(site_name)}</h1>\n  <ul>\n{items}\n  </ul>\n"
        f"  <p><small>{escape(NOTICE)}</small></p>\n</body>\n</html>\n"
    )


def render_sitemap(listings: list[Listing], base_url: str) -> str:
    base = base_url.rstrip("/")
    urls = "".join(
        f"  <url><loc>{escape(base)}/{escape(l.slug)}/</loc></url>\n" for l in listings
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{escape(base)}/</loc></url>\n{urls}</urlset>\n"
    )


ROBOTS = "User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n"


def build_site(
    outdir: str | Path,
    listings: list[Listing],
    base_url: str,
    site_name: str = "Contact",
) -> list[Path]:
    """Write the full static site. Returns every path written."""
    root = Path(outdir)
    root.mkdir(parents=True, exist_ok=True)
    written = [root / "index.html", root / "robots.txt", root / "sitemap.xml"]

    (root / "index.html").write_text(render_index(listings, site_name), "utf-8")
    (root / "robots.txt").write_text(ROBOTS.format(base=base_url.rstrip("/")), "utf-8")
    (root / "sitemap.xml").write_text(render_sitemap(listings, base_url), "utf-8")

    for listing in listings:
        page_dir = root / listing.slug
        page_dir.mkdir(parents=True, exist_ok=True)
        path = page_dir / "index.html"
        path.write_text(render(listing), "utf-8")
        written.append(path)
    return written

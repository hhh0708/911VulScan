"""Allowlist HTML sanitizer for LLM-generated report fragments.

The HTML overview report renders LLM-produced "remediation guidance" without
escaping (Go's ``template.HTML``), so that headings/lists/links display.
Because the LLM input embeds attacker-controlled finding text (descriptions
and vulnerable code snippets from the *scanned* repository), a prompt-injection
payload could otherwise smuggle ``<script>`` / ``onerror=`` into the report and
achieve stored XSS in whoever opens it.

This sanitizer rebuilds the fragment keeping only a safe tag/attribute
allowlist. Unknown tags are dropped (their text content is preserved);
``<script>``/``<style>`` content is discarded entirely.
"""

from __future__ import annotations

from html import escape
from html.parser import HTMLParser

# Tags safe to keep in a static report fragment.
_ALLOWED_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "strong", "em", "b", "i", "u", "code", "pre",
    "blockquote", "span", "div", "a", "table", "thead", "tbody",
    "tr", "th", "td",
}

# Tags whose *text content* must also be dropped, not just the tag.
_VOID_CONTENT_TAGS = {"script", "style", "template", "iframe", "object", "embed"}

# Void (self-closing) tags that never get a closing tag.
_VOID_TAGS = {"br", "hr"}

_CLASS_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ "
)


class _SanitizingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self._open: list[str] = []
        # Depth of currently-open dangerous element whose text we suppress.
        self._suppress_depth = 0

    def handle_starttag(self, tag: str, attrs):  # type: ignore[override]
        tag = tag.lower()
        if tag in _VOID_CONTENT_TAGS:
            self._suppress_depth += 1
            return
        if self._suppress_depth or tag not in _ALLOWED_TAGS:
            return
        self._out.append(self._render_starttag(tag, attrs))
        if tag not in _VOID_TAGS:
            self._open.append(tag)

    def handle_startendtag(self, tag: str, attrs):  # type: ignore[override]
        tag = tag.lower()
        if self._suppress_depth or tag in _VOID_CONTENT_TAGS:
            return
        if tag in _ALLOWED_TAGS:
            self._out.append(self._render_starttag(tag, attrs, self_close=True))

    def handle_endtag(self, tag: str):  # type: ignore[override]
        tag = tag.lower()
        if tag in _VOID_CONTENT_TAGS:
            if self._suppress_depth:
                self._suppress_depth -= 1
            return
        if self._suppress_depth or tag in _VOID_TAGS or tag not in _ALLOWED_TAGS:
            return
        if tag in self._open:
            # Close any tags opened after this one, then the tag itself.
            while self._open:
                top = self._open.pop()
                self._out.append(f"</{top}>")
                if top == tag:
                    break

    def handle_data(self, data: str):  # type: ignore[override]
        if self._suppress_depth:
            return
        self._out.append(escape(data))

    @staticmethod
    def _render_starttag(tag: str, attrs, self_close: bool = False) -> str:
        safe_attrs = ""
        for name, value in attrs:
            name = (name or "").lower()
            value = value or ""
            if name == "class":
                cleaned = "".join(c for c in value if c in _CLASS_SAFE).strip()
                if cleaned:
                    safe_attrs += f' class="{escape(cleaned, quote=True)}"'
            elif name == "href" and tag == "a":
                # Only same-document anchors (e.g. finding references) are safe.
                if value.startswith("#"):
                    safe_attrs += f' href="{escape(value, quote=True)}"'
            # All other attributes (on*, style, src, id, etc.) are dropped.
        close = " /" if self_close else ""
        return f"<{tag}{safe_attrs}{close}>"

    def result(self) -> str:
        # Close any tags the LLM left unbalanced.
        while self._open:
            self._out.append(f"</{self._open.pop()}>")
        return "".join(self._out)


def sanitize_report_html(html: str) -> str:
    """Return *html* reduced to a safe tag/attribute allowlist.

    On any parsing error, fall back to fully escaping the input so the report
    can never execute untrusted markup.
    """
    if not html:
        return ""
    try:
        parser = _SanitizingParser()
        parser.feed(html)
        parser.close()
        return parser.result()
    except Exception:
        return f"<p>{escape(html)}</p>"

"""Jinja environment for the shop-floor dashboard.

Autoescaping is on by default in ``Jinja2Templates`` and is left on. Alert headlines and
staff notes are attacker-influenced text: a disposition note is free-form input typed by
a member of staff and rendered back to a manager, so it is a stored-XSS vector if
escaping is ever disabled. There is no ``| safe`` filter anywhere in these templates.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from core import __version__

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.globals["app_version"] = __version__
templates.env.globals["product_name"] = "SentinelFloor"

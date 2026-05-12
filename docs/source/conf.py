"""Sphinx configuration for the warpgate documentation.

Docs are authored in Markdown; myst-parser bridges them into Sphinx
so Read the Docs can render the existing .md tree as-is.  No .rst
conversion needed.
"""
import os
import sys


# -- Project information -----------------------------------------------------

project = "warpgate"
author = "Matthew Roberts"
copyright = "2026, Matthew Roberts"

# Pull the running version straight from the installed package so the
# docs and the wheel never drift.  Fallback keeps RTD building even if
# the package isn't importable in the docs build environment.
try:
    sys.path.insert(0, os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", "src",
    )))
    from warpgate import __version__ as release  # noqa: E402
except Exception:
    release = "4.0.2"
version = release


# -- General configuration ---------------------------------------------------

extensions = [
    "myst_parser",
]

source_suffix = {
    ".md": "markdown",
    ".rst": "restructuredtext",
}

master_doc = "index"

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# myst-parser tweaks: enable a few extensions that play well with
# the existing markdown (fenced code with language tags, deflists,
# linkify autodetection so bare URLs render as links).
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "linkify",
    "substitution",
]
myst_heading_anchors = 3


# -- HTML output -------------------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = []
html_title = "warpgate"

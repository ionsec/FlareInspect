# ============================================================
# FlareInspect Sphinx Configuration
# ============================================================
import os

# -- Project information -------------------------------------------------
project = "FlareInspect"
copyright = "2026, IONSEC.IO"
author = "IONSEC.IO"
version = "1.2.0"
release = "1.2.0"

# -- General -----------------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.viewcode",
    "myst_parser",
    "sphinx_copybutton",
    "sphinx.ext.ifconfig",
    "sphinx.ext.graphviz",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Markdown ----------------------------------------------------------
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "tasklist",
    "strikethrough",
    "substitution",
    "linkify",
]

# -- Options HTML output -----------------------------------------------
html_theme = "sphinx_book_theme"

html_theme_options = {
    "repository_url": "https://github.com/ionsec/flareinspect",
    "repository_branch": "main",
    "use_repository_button": True,
    "use_issues_button": True,
    "use_edit_page_button": True,
    "home_page_in_toc": True,
    "show_navbar_depth": 2,
    "show_toc_level": 3,
    "navbar_align": "left",
    "extra_footer": (
        '<p style="margin:0;font-size:0.8rem">Built by <a href="https://ionsec.io" target="_blank">IONSEC.IO</a> &bull; '
        '<a href="https://github.com/ionsec/flareinspect" target="_blank">GitHub</a> &bull; MIT License</p>'
    ),
    "footer_start": ["copyright"],
    "footer_end": [],
    "collapse_navigation": False,
    "navigation_depth": 4,
    "sidebar-collapse": True,
    "show_topbar_edit_button": True,
}

html_context = {
    "github_user": "ionsec",
    "github_repo": "flareinspect",
    "github_version": "main",
    "doc_path": "docs",
}

html_title = "FlareInspect"
html_short_title = "FlareInspect"

html_favicon = "_static/favicon.svg"
html_logo = "_static/logo.svg"

html_static_path = ["_static"]

suppress_warnings = ["myst.xref_missing"]

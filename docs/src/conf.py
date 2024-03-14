# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "ska-low-csp-testware"
copyright = "2024 TOPIC Team"
author = "TOPIC Team"
release = "0.0.1"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.extlinks",
    "sphinx.ext.intersphinx",
    "autoapi.extension",
]

source_suffix = [".rst"]
exclude_patterns = []

pygments_style = "sphinx"

extlinks = {
    "jira": ("https://jira.skatelescope.org/browse/%s", "%s"),
}

intersphinx_mapping = {
    "ska-dev-portal": ("https://developer.skao.int/en/latest", None),
    "ska-tango-base": ("https://developer.skao.int/en/0.20.1", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "ska_ser_sphinx_theme"

html_context = {
    "theme_logo_only": True,
    "display_gitlab": True,
    "gitlab_user": "ska-telescope",
    "gitlab_repo": project,
    "gitlab_version": "main",
    "conf_py_path": "/docs/src/",  # Path in the checkout to the docs root
    "theme_vcs_pageview_mode": "edit",
    "suffix": ".rst",
}

# -- sphinx-autoapi configuration ----------------------------------------------
# https://github.com/readthedocs/sphinx-autoapi

autoapi_dirs = ["../../src/ska_low_csp_testware"]
autoapi_root = "api"

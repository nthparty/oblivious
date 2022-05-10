# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('..'))


# -- Project information -----------------------------------------------------

# The name and version are retrieved from `setup.py` in the root directory.
with open('../setup.py') as package_file:
    package = package_file.read()
project = package.split('name = "')[1].split('"')[0]
version = package.split('version = "')[1].split('"')[0]
release = version

author = 'Nth Party, Ltd.'
copyright = '2020, Nth Party, Ltd' # Period omitted; precedes punctuation.


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.napoleon'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build']

# Options to configure autodoc extension behavior.
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'special-members': True,
    'exclude-members': ','.join([
        '__init__',
        '__weakref__',
        '__module__',
        '__hash__',
        '__dict__'
    ])
}
autodoc_preserve_defaults = True

def autodoc_skip_member_handler(app, what, name, obj, skip, options):
    # Avoid emitting entries within `native` and `sodium` that are
    # duplicates of the top-level definitions.
    if name in ('sodium', 'native'):
        for method in [
          'scl', 'rnd', 'inv', 'smu', 'pnt', 'bas', 'mul', 'add', 'sub',
          'point', 'scalar'
        ]:
            if hasattr(obj, method):
                delattr(obj, method)

    return skip

def setup(app):
    app.connect('autodoc-skip-member', autodoc_skip_member_handler)


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Theme options for Read the Docs.
html_theme_options = {
    'display_version': True,
    'collapse_navigation': True,
    'navigation_depth': 1,
    'titles_only': True
}

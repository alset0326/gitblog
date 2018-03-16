#!/usr/bin/env python3
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals
from datetime import datetime
import pymdownx.emoji

AUTHOR = 'alset0326'
SITENAME = '/NOTES'
SITEURL = 'http://127.0.0.1:8000'

PATH = 'content'

TIMEZONE = 'Asia/Shanghai'

# DEFAULT_LANG = 'en'

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Blogroll
# LINKS = (('Github', 'https://github.com/alset0326'),)

# Social widget
SOCIAL = (('github', 'https://github.com/alset0326'),)

DEFAULT_PAGINATION = 20

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True

# ######################### Theme settings #########################

choose_theme = 'Flex attila'.split()[0]

if choose_theme == 'Flex':
    THEME = './themes/Flex'

    SITETITLE = SITENAME
    SITESUBTITLE = 'Alset0326'
    SITEDESCRIPTION = 'Remind Stuff'
    SITELOGO = '/images/logo.jpeg'
    FAVICON = '/images/logo.jpeg'
    BROWSER_COLOR = '#333333'
    PYGMENTS_STYLE = 'github'

    I18N_TEMPLATES_LANG = 'en'
    DEFAULT_LANG = 'en'
    OG_LOCALE = 'en_US'
    LOCALE = 'en_US'

    DATE_FORMATS = {
        'en': '%B %d, %Y',
    }

    HOME_HIDE_TAGS = False

    # MAIN_MENU = True
    # MENUITEMS = (('Archives', '/archives.html'),
    #              ('Categories', '/categories.html'),
    #              ('Tags', '/tags.html'),)

    # Use links instead
    LINKS = (('HOME', '/'), ('Archives', '/archives.html'),
             ('Categories', '/categories.html'),
             ('Tags', '/tags.html'),)

    COPYRIGHT_NAME = 'alset0326'
    COPYRIGHT_YEAR = '2017-' + str(datetime.now().year)

    PLUGIN_PATHS = ('pelican-plugins',)
    PLUGINS = ('sitemap', 'post_stats', 'i18n_subsites', 'related_posts', 'neighbors')

    JINJA_ENVIRONMENT = {'extensions': ['jinja2.ext.i18n']}

    SITEMAP = {
        'format': 'xml',
        'priorities': {
            'articles': 0.6,
            'indexes': 0.6,
            'pages': 0.5,
        },
        'changefreqs': {
            'articles': 'monthly',
            'indexes': 'daily',
            'pages': 'monthly',
        }
    }

    STATIC_PATHS = ['images', 'extra']

    EXTRA_PATH_METADATA = {
        'extra/custom.css': {'path': 'static/custom.css'},
    }
    CUSTOM_CSS = 'static/custom.css'

    GITHUB_CORNER_URL = 'https://github.com/alset0326/alset0326.github.io/issues'

    # RELATED_POSTS_MAX = 10

    MARKDOWN = {
        'extensions': [
            'markdown.extensions.tables',
            'markdown.extensions.sane_lists',
            # 'markdown.extensions.fenced_code',
            # 'codehilite',
            'pymdownx.magiclink',
            'pymdownx.betterem',
            'pymdownx.tilde',
            'pymdownx.emoji',
            'pymdownx.tasklist',
            'pymdownx.keys',
            'pymdownx.smartsymbols',
            'pymdownx.superfences',
            'pymdownx.highlight',
            'pymdownx.inlinehilite',
            'mdx_truly_sane_lists',
            'markdown_newtab',
        ],

        'extension_config': {
            "pymdownx.magiclink": {
                "repo_url_shortener": True,
                "repo_url_shorthand": True,
                "provider": "github",
                "user": "facelessuser",
                "repo": "pymdown-extensions"
            },
            "pymdownx.tilde": {
                "subscript": False
            },
            "pymdownx.emoji": {
                "emoji_index": pymdownx.emoji.gemoji,
                "emoji_generator": pymdownx.emoji.to_png,
                "alt": "short",
                "options": {
                    "attributes": {
                        "align": "absmiddle",
                        "height": "20px",
                        "width": "20px"
                    },
                    "image_path": "https://assets-cdn.github.com/images/icons/emoji/unicode/",
                    "non_standard_image_path": "https://assets-cdn.github.com/images/icons/emoji/"
                }
            },
            'mdx_truly_sane_lists': {
                'nested_indent': 2,
                'truly_sane': True,
            },
            'pymdownx.highlight': {
                'css_class': 'highlight',
                'guess_lang': False,
                'pygments_style': 'default',
                'noclasses=': False,
                'use_pygments': True,
                'linenums': False,
                'extend_pygments_lang': []
            }
        },
    }

elif choose_theme == 'attila':
    THEME = './themes/attila'

del choose_theme

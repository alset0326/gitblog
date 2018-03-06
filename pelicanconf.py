#!/usr/bin/env python3
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

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

PLUGIN_PATHS = ('pelican-plugins',)

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
    COPYRIGHT_YEAR = '2017-2018'

    PLUGINS = ['sitemap', 'i18n_subsites']

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

    # GITHUB_CORNER_URL = 'https://github.com/alset0326'

elif choose_theme == 'attila':
    THEME = './themes/attila'

del choose_theme

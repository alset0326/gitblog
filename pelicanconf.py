#!/usr/bin/env python3
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals
from datetime import datetime
import pymdownx.emoji

AUTHOR = 'alset0326'
SITENAME = 'A-NOTES'
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
github_url = 'https://github.com/alset0326'
SOCIAL = (('github', github_url),)

DEFAULT_PAGINATION = 20

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True

# ######################### Theme settings #########################
# back themes:
# https://github.com/ingwinlu/pelican-twitchy.git
# https://github.com/arulrajnet/attila.git
# https://github.com/onur/medius.git
# https://github.com/jsliang/pelican-fresh.git
# https://github.com/aquatix/voidy-bootstrap.git

choose_theme = 'Flex m.css'.split()[-1]

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
            'markdown.extensions.toc',
            # 'markdown.extensions.fenced_code',
            # 'codehilite',
            'pymdownx.b64',
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

        'extension_configs': {
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
                'noclasses': False,
                'use_pygments': True,
                'linenums': False,
                'extend_pygments_lang': []
            }
        },
    }

elif choose_theme == 'm.css':
    THEME = './themes/m.css/pelican-theme'

    THEME_STATIC_DIR = 'static'
    DIRECT_TEMPLATES = ['index']

    # M_CSS_FILES = (
    #     'https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,400i,600,600i%7CSource+Code+Pro:400,400i,600',
    #     '/static/m-dark.css',
    # )
    # M_THEME_COLOR = '#22272e'
    M_CSS_FILES = (
        '/extra/normalize.css',
        'https://fonts.googleapis.com/css?family=Libre+Baskerville:400,400i,700,700i%7CSource+Code+Pro:400,400i,600',
        '/static/m-light.compiled.css',
        '/extra/highlight.css',
    )
    M_THEME_COLOR = '#cb4b16'

    PLUGIN_PATHS = ['./themes/m.css/pelican-plugins']
    PLUGINS = ['m.htmlsanity']

    # M_BLOG_NAME = 'Your Brand Blog'
    # M_BLOG_URL = 'blog/'

    M_FAVICON = ('/images/logo.jpeg', 'image/jpeg')
    # M_BLOG_FAVICON = ('favicon-blog.png', 'image/png')

    # # Header setting
    # M_SITE_LOGO = '/images/logo.jpeg'
    M_SITE_LOGO_TEXT = 'A-NOTE To Remind Something'
    # # link ti­tle, URL, page slug of the corresponding page (used to highlight currently active menu item),
    # # fourth is a list of submenu items (which are 3-tuples link title, URL and page slug).
    M_LINKS_NAVBAR1 = (('HOME', '/', 'index', ()),)
    # M_LINKS_NAVBAR2 = (('Blog', 'blog/', '[blog]', [('News', 'blog/news/', ''), ('Archive', 'blog/archive/', '')]),)
    M_LINKS_NAVBAR2 = (('GITHUB', github_url, '', ()),)

    # # Floor settings
    # # title, URL
    M_LINKS_FOOTER1 = (('Projects', github_url + '?tab=repositories'), ('peda-arm', github_url + '/peda-arm'),
                       ('zio3', github_url + '/zio3'),)
    M_LINKS_FOOTER2 = (('Author', '/'), ('Alset0326', SITEURL + '/author/alset0326.html'),)
    M_LINKS_FOOTER3 = (('Contact', github_url), ('E-mail', 'mailto:alset0326@gmail.com'), ('GitHub', github_url),)
    # M_FINE_PRINT = SITENAME + '. Powered by `Pelican <https://getpelican.com>`_ and `m.css <http://mcss.mosra.cz>`_.'

    # # Twitter settings
    # M_BLOG_NAME = "Your Brand Blog"
    # M_BLOG_URL = 'http://blog.your.brand/'
    # M_BLOG_DESCRIPTION = "Your Brand is the brand that provides all that\'s needed."
    # M_SOCIAL_TWITTER_SITE = '@your.brand'
    # M_SOCIAL_TWITTER_SITE_ID = 1234567890
    # M_SOCIAL_IMAGE = 'http://your.brand/static/site.png'
    # M_SOCIAL_BLOG_SUMMARY = "This is the brand you need"

    # # enable News on index PAGE
    M_NEWS_ON_INDEX = ("Latest news on the blog", 3)

    # M_SHOW_AUTHOR_LIST = True
    # M_HIDE_ARTICLE_SUMMARY = True
    M_COLLAPSE_FIRST_ARTICLE = True

    DEFAULT_PAGINATION = 20

    STATIC_PATHS = ['images', 'extra']

    MARKDOWN = {
        'extensions': [
            'markdown.extensions.tables',
            'markdown.extensions.sane_lists',
            'markdown.extensions.toc',
            # 'markdown.extensions.fenced_code',
            # 'codehilite',
            'pymdownx.b64',
            'pymdownx.magiclink',
            'pymdownx.betterem',
            'pymdownx.tilde',
            'pymdownx.emoji',
            'pymdownx.tasklist',
            'pymdownx.keys',
            'pymdownx.smartsymbols',
            'pymdownx.highlight',
            'pymdownx.inlinehilite',
            'pymdownx.superfences',
            'mdx_truly_sane_lists',
            'markdown_newtab',
        ],

        'extension_configs': {
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
            'pymdownx.superfences': {
                'disable_indented_code_blocks': True
            },
            'pymdownx.highlight': {
                'css_class': 'highlight',
                'guess_lang': False,
                'pygments_style': 'default',
                'noclasses': False,
                'use_pygments': True,
                'linenums': False,
                'extend_pygments_lang': []
            }
        },
    }

del choose_theme
del github_url

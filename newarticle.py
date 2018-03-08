#!/usr/bin/env python3

import datetime
import sys
import os


# title, new, category, tags, slug, summary
def generate(**kwargs):
    template = '''Title: {title}
Date: {now}
Modified: {now}
Category: {category}
Tags: {tags}
Slug: {slug}
Authors: Alset0326
Summary: {summary}

# {title}

'''

    return template.format(**kwargs)


def main():
    if len(sys.argv) != 2:
        print('Usage:\t{} article_dir'.format(sys.argv[0]))
    path = sys.argv[1]
    title = input('Title: ')
    category = input('Category: ')
    tags = input('Tags: ')
    _slug = title.lower().replace(' ', '-')
    slug = input('Slug ({}): '.format(_slug))
    if not slug:
        slug = _slug
    summary = input('Summary: ')
    now = datetime.datetime.now().isoformat(sep=' ')

    s = generate(title=title, category=category, tags=tags, slug=slug, summary=summary, now=now)

    md_path = os.path.join(path, slug + '.md')
    while os.path.exists(md_path):
        slug = input('Article slug exist. Please reinput: ')
        md_path = os.path.join(path, slug + '.md')
    open(md_path, 'wt').write(s)
    os.system('open ' + md_path)


if __name__ == '__main__':
    main()

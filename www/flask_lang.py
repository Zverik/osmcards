import os
from ruamel.yaml import YAML
from flask import current_app, request, g


def merge_dict(target, other):
    for k, v in other.items():
        if isinstance(v, dict):
            node = target.setdefault(k, {})
            merge_dict(node, v)
        else:
            target[k] = v


def _load_language(base, path, lang):
    yaml = YAML()
    with open(os.path.join(base, 'lang', path or '', 'en.yaml'), 'r') as f:
        data = yaml.load(f)
        data = data[list(data.keys())[0]]
    lang_file = os.path.join(base, 'lang', path or '', lang + '.yaml')
    if os.path.exists(lang_file):
        with open(lang_file, 'r') as f:
            lang_data = yaml.load(f)
            merge_dict(data, lang_data[list(lang_data.keys())[0]])
    # return to_unicode(data)
    return data


def get_supported_languages(base):
    return set([x[:x.index('.')]
                for x in os.listdir(os.path.join(base, 'lang'))
                if '.yaml' in x])


def get_language_from_request():
    base = current_app.config['BASE_DIR']
    supported = get_supported_languages(base)
    accepted = request.headers.get('Accept-Language', '')
    lang = 'en'
    for lpart in accepted.split(','):
        if ';' in lpart:
            lpart = lpart[:lpart.index(';')]
        pieces = lpart.strip().split('-')
        if len(pieces) >= 2:
            testlang = '{}_{}'.format(pieces[0].lower(), pieces[1].upper())
            if testlang in supported:
                lang = testlang
                break
        if len(pieces) == 1 and pieces[0].lower() in supported:
            lang = pieces[0].lower()
            break
    return lang


def load_language(lang, path=''):
    base = current_app.config['BASE_DIR']
    g.supported_languages = get_supported_languages(base)
    if not lang:
        lang = get_language_from_request()
    g.lang = _load_language(base, path, lang)

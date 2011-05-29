#!/usr/bin/python3

"""Shorten URLs using Google's http://goo.gl/ URL shortening service."""

import http.client
import json
import re
import urllib.parse


# http://daringfireball.net/2010/07/improved_regex_for_matching_urls
_EXTRACT_URL_RE = re.compile(r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))')


class Error(Exception):
    pass


def shorten_url(long_url, api_key=''):
    """Return a http://goo.gl/ shortened version of long_url; '' on failure.

    If no api_key is specified your queries may be rate limited by goo.gl.
    SSL is used but certificates are not verified.

    Args:
        long_url: The URL you want shortened.
        api_key: Your optional goo.gl Google API key.
    Returns:
        The shortened URL.
    Raises:
        Error: On any failure to communicate properly with the API server.
    """
    if api_key:
        query_string = '?key=' + api_key
    else:
        query_string = ''
    http_conn = http.client.HTTPSConnection('www.googleapis.com')
    try:
        http_conn.request('POST', '/urlshortener/v1/url' + query_string,
                          headers={'Content-Type': 'application/json'},
                          body=json.dumps({"longUrl": long_url}))
        response = http_conn.getresponse()
        if 200 <= response.status < 300:
            json_data = response.read(8192).decode('utf8')
            try:
                goo_gl_response = json.loads(json_data)
            except ValueError:
                raise Error('Could not parse server response.')
            if 'id' in goo_gl_response:
                return goo_gl_response['id']
    except EnvironmentError as e:
        raise Error('server communication error: {}'.format(e))
    finally:
        http_conn.close()
    raise Error('server {} error.'.format(response.status))


def shorten_long_urls(text, long_len=55, api_key='', include_note=False,
                      max_note_len=110):
    """Return text with all long URLs replaced with short ones.

    Args:
        long_len: The length of a URL before it will be shortened.
        api_key: Optional, the goo.gl API key for your application.
        include_note: If true a parenthesized summary of the url
            domain and last path elements will be included after the
            short URL.
        max_note_len: The maximum length of an included note before it
            is elided.

    Returns:
        text with URLs replaces as appropriate.
    """
    urls = [group[0] for group in _EXTRACT_URL_RE.findall(text)]
    if not urls:
        return text
    for url in urls:
        if len(url) <= long_len:
            continue
        try:
            short_url = shorten_url(url, api_key=api_key)
        except Error:
            pass  # Best Effort: ignore and skip failed shortens.
        else:
            if include_note:
                try:
                    note = _generate_url_note(url, max_note_len)
                except Exception:
                    pass
                short_url = '%s (%s)' % (short_url, note)
            text = text.replace(url, short_url)
    return text


# Used to strip off the ending three letter or pair or two letter TLDs + port.
_STRIP_DOMAIN_END_RE = re.compile(r'\.[a-z]{2,3}(\.[a-z]{2})?(:\d+)?$', re.I)


def _generate_url_note(url, max_note_len):
    """Given a URL generate some summary text of the URL."""
    parsed = urllib.parse.urlparse(url)
    path_parts = parsed.path.split('/')
    max_path_part = ''
    for part in reversed(path_parts):
        if len(part) > len(max_path_part):
            max_path_part = part
    tasty_path = max_path_part
    domain = _STRIP_DOMAIN_END_RE.sub('', parsed.netloc)
    if len(domain) > max_note_len - len(tasty_path) - 3:
        note = tasty_path
    elif tasty_path and domain:
        note = '%s [%s]' % (tasty_path, domain)
    elif domain:
        note = '[%s]' % (domain,)
    else:
        raise Error('cannot make a note for this url ' + str(parsed))
    return note



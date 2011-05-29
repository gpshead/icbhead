#!/usr/bin/python3

"""Unittests for the goo_gl URL shortening module."""

import unittest
import goo_gl


# http://daringfireball.net/2010/07/improved_regex_for_matching_urls
_HTTP_URLS_TO_MATCH = (
    'https://foo.com/blah_blah',
    'http://foo.com/blah_blah/',
    '(Something like http://foo.com/blah_blah)',
    'http://foo.com/blah_blah_(wikipedia)',
    'http://foo.com/more_(than)_one_(parens)',
    '(Something like http://foo.com/blah_blah_(wikipedia))',
    'http://foo.com/blah_(wikipedia)#cite-1',
    'http://foo.com/blah_(wikipedia)_blah#cite-1',
    'http://foo.com/unicode_(✪)_in_parens',
    'http://foo.com/(something)?after=parens',
    'http://foo.com/blah_blah.',
    'http://foo.com/blah_blah/.',
    '<http://foo.com/blah_blah>',
    '<http://foo.com/blah_blah/>',
    'http://foo.com/blah_blah,',
    'http://www.extinguishedscholar.com/wpglob/?p=364.',
    'http://✪df.ws/1234',
    'http://➡.ws/䨹',
    '<tag>http://example.com</tag>',
    'http://example.com/something?with,commas,in,url, but not at end',
    'http://www.asianewsphoto.com/(S(neugxif4twuizg551ywh3f55))/Web_ENG/View_DetailPhoto.aspx?PicId=752',
    'http://www.asianewsphoto.com/(S(neugxif4twuizg551ywh3f55))',
    'http://lcweb2.loc.gov/cgi-bin/query/h?pp/horyd:@field(NUMBER+@band(thc+5a46634))',
)


class URLMatchTests(unittest.TestCase):
    def test_EXTRACT_URL_RE(self):
        for url in _HTTP_URLS_TO_MATCH:
            match = goo_gl._EXTRACT_URL_RE.search(url)
            self.assertTrue(match, 'url {} failed to match.'.format(url))

    def test_EXTRACT_URL_RE_findall(self):
        lots_of_urls = '. '.join(_HTTP_URLS_TO_MATCH)
        found_urls = goo_gl._EXTRACT_URL_RE.findall(lots_of_urls)
        self.assertEqual(len(found_urls), len(_HTTP_URLS_TO_MATCH))


@unittest.skip('Disabled by default; requires the intarwebs.')
class ShortenURLTest(unittest.TestCase):
    def test_shorten_url(self):
        self.assertEqual('http://goo.gl/fbsS',
                         goo_gl.shorten_url('http://www.google.com/', api_key=''))

    def test_shorten_url_fail(self):
        self.assertRaises(goo_gl.Error, goo_gl.shorten_url, 'not a url: unittest', api_key='')


class ShortenLongURLsTest(unittest.TestCase):
    @staticmethod
    def _mock_shorten_url(url, api_key=''):
        return 'http://mock/' + hex(hash(url))[-6:]

    _text = """long body of text with https://example.com/urls/in/it
    as well as some http://goo.gl/shorter urls in it.
    http://a0.twimg.com/profile_images/710094757/3468746237_54b25f56cb_t.jpg
    """
    _long_urls = ('https://example.com/urls/in/it',
                  'http://a0.twimg.com/profile_images/710094757/'
                  '3468746237_54b25f56cb_t.jpg')
    _long_url_notes = ('urls [example]',
                       '3468746237_54b25f56cb_t.jpg [a0.twimg]')

    def setUp(self):
        self._ORIG_shorten_url = goo_gl.shorten_url
        goo_gl.shorten_url = self._mock_shorten_url

        # Setup the test data.
        self._fake_short_urls = [self._mock_shorten_url(url) for url in
                                 self._long_urls]
        self._test_url_info = zip(self._long_urls, self._fake_short_urls,
                                  self._long_url_notes)

    def tearDown(self):
        goo_gl.shorten_url = self._ORIG_shorten_url

    def test_shorten_long_urls(self):
        new_text = goo_gl.shorten_long_urls(self._text, 26)
        self.assertLess(len(new_text), len(self._text))
        self.assertIn('http://goo.gl/shorter', new_text)
        for long_url, fake_short_url, _ in self._test_url_info:
            self.assertIn(long_url, self._text)
            self.assertNotIn(long_url, new_text)
            self.assertIn(fake_short_url, new_text)

    def test_shorten_long_urls_with_note(self):
        new_text = goo_gl.shorten_long_urls(self._text, 26, include_note=True)
        self.assertIn('http://goo.gl/shorter', new_text)
        for long_url, fake_short_url, url_note in self._test_url_info:
            self.assertIn(long_url, self._text)
            self.assertNotIn(url_note, self._text)
            self.assertNotIn(long_url, new_text)
            self.assertIn(url_note, new_text)
            self.assertIn(fake_short_url, new_text)

    def test_generate_url_note(self):
        note = goo_gl._generate_url_note('http://example.com/', 50)
        self.assertEqual('[example]', note)
        note = goo_gl._generate_url_note('http://example.com/foo/bar/xx', 50)
        self.assertEqual('bar [example]', note)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3

import unittest

import icb

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
            match = icb._EXTRACT_URL_RE.search(url)
            self.assertTrue(match, 'url {} failed to match.'.format(url))

    def test_EXTRACT_URL_RE_findall(self):
        lots_of_urls = '. '.join(_HTTP_URLS_TO_MATCH)
        found_urls = icb._EXTRACT_URL_RE.findall(lots_of_urls)
        self.assertEqual(len(found_urls), len(_HTTP_URLS_TO_MATCH))


# This test requires internet connectivity.
@unittest.skip('Disabled by default; requires the intarweb.')
class ShortenURLTest(unittest.TestCase):
    def test_shorten_url(self):
        self.assertEqual('http://goo.gl/fbsS',
                         icb.shorten_url('http://www.google.com/', api_key=''))

    def test_shorten_url_fail(self):
        self.assertEqual('', icb.shorten_url('not a url: unittest', api_key=''))


class ShortenLongURLsTest(unittest.TestCase):
    def setUp(self):
        self._ORIG_shorten_url = icb.shorten_url
        icb.shorten_url = lambda url: str(hash(url))

    def tearDown(self):
        icb.shorten_url = self._ORIG_shorten_url

    def test_shorten_long_urls(self):
        text = """long body of text with https://example.com/urls/in/it
        as well as some http://goo.gl/shorter urls in it.
        http://a0.twimg.com/profile_images/710094757/3468746237_54b25f56cb_t.jpg
        """
        long_urls = ('https://example.com/urls/in/it',
                     'http://a0.twimg.com/profile_images/710094757/'
                     '3468746237_54b25f56cb_t.jpg')
        fake_short_urls = [str(hash(url)) for url in long_urls]
        new_text = icb.shorten_long_urls(text, 26)
        self.assertIn('http://goo.gl/shorter', new_text)
        for long_url, fake_short_url in zip(long_urls, fake_short_urls):
            self.assertIn(long_url, text)
            self.assertNotIn(long_url, new_text)
            self.assertIn(fake_short_url, new_text)


class IcbConnWrappingTests(unittest.TestCase):
    def setUp(self):
        self._ORIG_read_config_file = icb.IcbConn.read_config_file
        icb.IcbConn.read_config_file = lambda self: None
        self.conn = icb.IcbConn()

    def tearDown(self):
        icb.IcbConn.read_config_file = self._ORIG_read_config_file

    def test_wrap_and_encode_empty(self):
        self.assertRaises(ValueError, self.conn._wrap_and_encode, '', 99)

    def test_wrap_and_encode_bad_max(self):
        self.assertRaises(ValueError, self.conn._wrap_and_encode, 'line', 9)

    def test_wrap_and_encode_1line(self):
        self.assertEqual(self.conn._wrap_and_encode('simple line', 99),
                         [b'simple line'])

    def test_wrap_and_encode_2line(self):
        text = 'simple line with enough words to wrap into two.'
        lines = self.conn._wrap_and_encode(text, 30)
        rejoined = b' '.join(lines)
        self.assertEqual(text.encode('ascii'), rejoined)
        self.assertEqual(len(lines), 2)

    def test_wrap_and_encode_with_encoding_expansion(self):
        text = '✪' * 200
        self.conn.codec = 'utf8'  # Force a multibyte character encoding.
        lines = self.conn._wrap_and_encode(text, 70)
        rejoined = b''.join(lines)
        self.assertEqual(self.conn._encode(text), rejoined)
        self.assertGreater(len(lines), 3)
        for line in lines:
            self.assertLessEqual(len(line), 70)


if __name__ == '__main__':
    unittest.main()

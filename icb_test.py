#!/usr/bin/python3

import unittest
import icb


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

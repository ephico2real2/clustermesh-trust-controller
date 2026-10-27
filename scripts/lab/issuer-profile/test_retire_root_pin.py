"""Pure tests of retire_root_pin.py; no node or Kubernetes access."""
import unittest

from retire_root_pin import retired

OLD, MESH = '0c28af9e' + '0' * 56, '6c12c735' + '0' * 56


class RetiredTests(unittest.TestCase):
    def test_retires_one_pin_and_keeps_every_other_field(self):
        pins = {'cluster': 'cmtc-b', 'rootPins': [OLD, MESH], 'minimumSequence': '6070'}
        self.assertEqual(retired(pins, OLD), {'cluster': 'cmtc-b', 'rootPins': [MESH], 'minimumSequence': '6070'})
        self.assertEqual(pins['rootPins'], [OLD, MESH])

    def test_refuses_an_absent_or_the_last_pin(self):
        with self.assertRaisesRegex(ValueError, 'not pinned'):
            retired({'rootPins': [MESH]}, OLD)
        with self.assertRaisesRegex(ValueError, 'last root pin'):
            retired({'rootPins': [MESH]}, MESH)


if __name__ == '__main__':
    unittest.main()

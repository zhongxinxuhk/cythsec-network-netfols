"""Reference output normalization retains protocol semantics across tshark releases."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dhcp_reference', ROOT / 'scripts/verify/check-dhcpv4.py')
dhcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dhcp)


class DhcpReferenceTests(unittest.TestCase):
    def pdml(self, shown):
        fragments = ''.join(
            f'<field name="dhcp.option.type" show="12" pos="{pos}" value="0c01{value:02x}"/>'
            for pos, value in [(86, ord('c')), (150, ord('b')), (288, ord('a'))]
        )
        display = ''.join(f'<field name="dhcp.option.hostname" show="{value}"/>' for value in shown)
        return f'<pdml><packet><proto name="dhcp" pos="42">{fragments}{display}</proto></packet></pdml>'

    def test_fragmented_and_reassembled_display_have_same_rfc_order(self):
        for shown in [('c', 'b', 'a'), ('abc',)]:
            with self.subTest(shown=shown):
                self.assertEqual(dhcp.overload_hostname(self.pdml(shown)), 'abc')

    def test_missing_duplicate_or_changed_reference_values_are_rejected(self):
        for shown in [('a', 'b'), ('a', 'a', 'c'), ('abd',), ('cba',)]:
            with self.subTest(shown=shown), self.assertRaises(AssertionError):
                dhcp.overload_hostname(self.pdml(shown))
        broken = self.pdml(('abc',)).replace('value="0c0161"', 'value="0c0261"')
        with self.assertRaises(AssertionError):
            dhcp.overload_hostname(broken)


if __name__ == '__main__':
    unittest.main()

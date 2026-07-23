import unittest

from utils.proxy_node_stats import _merge_exclude_filter, _node_from_chains


class ProxyNodeStatsTests(unittest.TestCase):
    def test_node_from_chains_returns_real_leaf(self):
        self.assertEqual(
            "新加坡YouTube@小青科学网_2",
            _node_from_chains(["新加坡YouTube@小青科学网_2", "LB-GLOBAL-REFINED"], "LB-GLOBAL-REFINED"),
        )

    def test_merge_exclude_filter_escapes_node_name_once(self):
        first = _merge_exclude_filter("港|HK", "新加坡YouTube@小青科学网_2")
        self.assertIn(r"新加坡YouTube@小青科学网_2", first)
        self.assertEqual(first, _merge_exclude_filter(first, "新加坡YouTube@小青科学网_2"))


if __name__ == "__main__":
    unittest.main()

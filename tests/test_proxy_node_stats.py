import unittest

from utils.proxy_node_stats import (
    UNCAPTURED_NODE,
    _merge_exclude_filter,
    _node_from_chains,
    _resolve_leaf_node,
    is_real_exit_node,
    select_target_node_pool_group,
)


class ProxyNodeStatsTests(unittest.TestCase):
    def test_node_from_chains_returns_real_leaf(self):
        self.assertEqual(
            "新加坡YouTube@小青科学网_2",
            _node_from_chains(["新加坡YouTube@小青科学网_2", "LB-GLOBAL-REFINED"], "LB-GLOBAL-REFINED"),
        )

    def test_node_from_chains_skips_direct_global_lb(self):
        self.assertEqual("", _node_from_chains(["DIRECT"], "GLOBAL"))
        self.assertEqual("", _node_from_chains(["GLOBAL"], "GLOBAL"))
        self.assertEqual("", _node_from_chains(["LB-GLOBAL-REFINED", "GLOBAL"], "GLOBAL"))
        self.assertEqual(
            "sg-01",
            _node_from_chains(["sg-01", "LB-GLOBAL-REFINED", "GLOBAL"], "GLOBAL"),
        )

    def test_is_real_exit_node_rejects_strategy_names(self):
        self.assertFalse(is_real_exit_node("DIRECT"))
        self.assertFalse(is_real_exit_node("GLOBAL"))
        self.assertFalse(is_real_exit_node("LB-GLOBAL-REFINED"))
        self.assertFalse(is_real_exit_node(UNCAPTURED_NODE))
        self.assertTrue(is_real_exit_node("新加坡YouTube@小青科学网_2"))

    def test_select_target_node_pool_group_prefers_biggest_when_global(self):
        proxy_map = {
            "DIRECT": {"type": "Direct", "all": []},
            "REJECT": {"type": "Reject", "all": []},
            "GLOBAL": {
                "type": "Selector",
                "all": ["DIRECT", "REJECT", "LB-GLOBAL-REFINED", "LB-SMALL"],
                "now": "LB-GLOBAL-REFINED",
            },
            "LB-GLOBAL-REFINED": {
                "type": "LoadBalance",
                "all": ["sg-01", "sg-02", "jp-01", "DIRECT"],
                "now": "",
            },
            "LB-SMALL": {
                "type": "LoadBalance",
                "all": ["hk-01"],
                "now": "hk-01",
            },
        }
        name, count = select_target_node_pool_group(proxy_map, "GLOBAL")
        self.assertEqual("LB-GLOBAL-REFINED", name)
        # DIRECT inside the pool is not a real exit
        self.assertEqual(3, count)

    def test_resolve_leaf_node_does_not_return_group_markers(self):
        proxy_map = {
            "GLOBAL": {
                "type": "Selector",
                "all": ["DIRECT", "LB-GLOBAL-REFINED"],
                "now": "LB-GLOBAL-REFINED",
            },
            "LB-GLOBAL-REFINED": {
                "type": "LoadBalance",
                "all": ["sg-01", "sg-02"],
                "now": "",
            },
            "sg-01": {"type": "Shadowsocks", "history": [{"delay": 120}]},
            "sg-02": {"type": "Shadowsocks", "history": [{"delay": 90}]},
        }
        group, node, delay = _resolve_leaf_node(proxy_map, "GLOBAL")
        self.assertEqual("LB-GLOBAL-REFINED", group)
        self.assertEqual("", node)
        self.assertIsNone(delay)

        proxy_map["LB-GLOBAL-REFINED"]["now"] = "sg-02"
        group, node, delay = _resolve_leaf_node(proxy_map, "GLOBAL")
        self.assertEqual("LB-GLOBAL-REFINED", group)
        self.assertEqual("sg-02", node)
        self.assertEqual(90, delay)

    def test_merge_exclude_filter_escapes_node_name_once(self):
        first = _merge_exclude_filter("港|HK", "新加坡YouTube@小青科学网_2")
        self.assertIn(r"新加坡YouTube@小青科学网_2", first)
        self.assertEqual(first, _merge_exclude_filter(first, "新加坡YouTube@小青科学网_2"))


if __name__ == "__main__":
    unittest.main()

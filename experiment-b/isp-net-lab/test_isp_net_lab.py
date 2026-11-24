import unittest

import bgp_filter
import observer
import route_monitor


class FakeRouter:
    """Keeps a running config and applies the vtysh commands the adapter sends."""

    def __init__(self):
        self.lines: list[str] = []
        self.route_map = False
        self.applied = False
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        cmds = [args[i + 1] for i, a in enumerate(args) if a == "-c"]
        if cmds == ["show running-config"]:
            cfg = list(self.lines)
            if self.route_map:
                cfg.append("route-map CUST-IN permit 10")
            if self.applied:
                cfg.append(" neighbor 10.0.4.2 route-map CUST-IN in")
            return "\n".join(cfg)
        for c in cmds:
            if c == "no ip prefix-list CUST-IN":
                self.lines = []
            elif c.startswith("ip prefix-list CUST-IN"):
                self.lines.append(c)
            elif c.startswith("route-map CUST-IN permit"):
                self.route_map = True
            elif c == "no route-map CUST-IN":
                self.route_map = False
            elif c == "neighbor 10.0.4.2 route-map CUST-IN in":
                self.applied = True
            elif c == "no neighbor 10.0.4.2 route-map CUST-IN in":
                self.applied = False
        return ""


class GrammarTests(unittest.TestCase):
    def test_valid_and_invalid(self):
        bgp_filter.validate("ip prefix-list CUST-IN seq 10 permit 198.51.100.0/24 le 24\n")
        for bad in ("ip prefix-list OTHER seq 10 permit 198.51.100.0/24",
                    "ip prefix-list CUST-IN seq 10 permit 198.51.100.1/24",
                    "ip prefix-list CUST-IN seq 10 permit 198.51.100.0/24 le 20",
                    "router bgp 1",
                    "ip prefix-list CUST-IN seq 10 permit 10.0.0.0/8\nip prefix-list CUST-IN seq 10 deny 0.0.0.0/0 le 32"):
            with self.assertRaises(ValueError, msg=bad):
                bgp_filter.validate(bad)


class AdapterTests(unittest.TestCase):
    def test_write_read_and_restore_empty(self):
        r = FakeRouter()
        a = bgp_filter.FrrInboundFilterAdapter(r, "10.0.4.2", 65100)
        self.assertEqual(a.read(), "")
        content = route_monitor.filter_for(["198.51.100.0/24"])
        a.write(content)
        self.assertEqual(a.read(), content)
        self.assertTrue(r.applied and r.route_map)
        a.write("")
        self.assertEqual(a.read(), "")
        self.assertFalse(r.applied or r.route_map)

    def test_unapplied_list_is_visible(self):
        r = FakeRouter()
        r.lines = ["ip prefix-list CUST-IN seq 10 permit 198.51.100.0/24 le 24"]
        a = bgp_filter.FrrInboundFilterAdapter(r, "10.0.4.2", 65100)
        self.assertTrue(a.read().startswith("# prefix-list present but not applied"))

    def test_write_refuses_bad_content(self):
        a = bgp_filter.FrrInboundFilterAdapter(FakeRouter(), "10.0.4.2", 65100)
        with self.assertRaises(ValueError):
            a.write("ip route 0.0.0.0/0 Null0")


class MonitorTests(unittest.TestCase):
    def test_more_specific_of_another_prefix_is_unauthorized(self):
        reg = ["198.51.100.0/24"]
        got = route_monitor.unauthorized(["198.51.100.0/24", "198.51.100.128/25", "203.0.113.0/25"], reg)
        self.assertEqual(got, ["203.0.113.0/25"])

    def test_filter_for_registry(self):
        self.assertEqual(route_monitor.filter_for(["198.51.100.0/24"]),
                         "ip prefix-list CUST-IN seq 10 permit 198.51.100.0/24 le 24\n")


class ObserverTests(unittest.TestCase):
    def test_hijack_detection_from_observation(self):
        clean = {"content_answer": "content", "content_routes": {"pe1": {"origin_as": 65000}}}
        self.assertFalse(observer.hijacked(clean))
        self.assertTrue(observer.hijacked(dict(clean, content_answer="attacker")))
        self.assertTrue(observer.hijacked({"content_answer": "content", "content_routes": {"pe2": {"origin_as": 65200}}}))


if __name__ == "__main__":
    unittest.main()

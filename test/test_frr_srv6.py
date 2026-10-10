"""No VPP required: selected-route stream semantics and recovery."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("frr_srv6", Path(__file__).parents[1] / "agent/frr_srv6.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.agent = module.Adapter(None, {"asn": 65000, "services": [{"evi": 100, "vni": 10100}]})
        self.agent.cli = Mock()
        self.agent.frr = Mock()

    def route(self, kind, key, sid="5f00:0:2:100:1::", add=True):
        self.agent.remote_event({"event": "route", "vni": 10100, "type": kind,
                                 "key": key, "sid": sid, "add": add})

    def test_snapshot_is_atomic_then_updates_and_withdrawals(self):
        self.agent.remote_event({"event": "begin"})
        self.route(2, "02:00:00:00:00:01")
        self.route(3, "2001:db8::3", "5f00:0:2:100:2::")
        self.agent.cli.assert_not_called()
        self.agent.remote_event({"event": "end"})
        self.assertEqual(self.agent.cli.call_count, 2)
        self.route(2, "02:00:00:00:00:01", "5f00:0:3:100:1::")
        self.agent.cli.assert_called_with("evpn srv6 mac add evi 100 02:00:00:00:00:01 sid 5f00:0:3:100:1::")
        self.route(2, "02:00:00:00:00:01", add=False)
        self.agent.cli.assert_called_with("evpn srv6 mac del evi 100 02:00:00:00:00:01")

    def test_imet_shared_sid_removed_only_after_last_route(self):
        self.route(3, "2001:db8::3")
        self.route(3, "2001:db8::4")
        self.assertEqual(self.agent.cli.call_count, 1)
        self.route(3, "2001:db8::3", add=False)
        self.assertEqual(self.agent.cli.call_count, 1)
        self.route(3, "2001:db8::4", add=False)
        self.agent.cli.assert_called_with("evpn srv6 imet del evi 100 sid 5f00:0:2:100:1::")

    def test_reconnect_snapshot_removes_routes_missing_from_snapshot(self):
        self.route(2, "02:00:00:00:00:01")
        self.agent.remote_event({"event": "begin"})
        self.agent.remote_event({"event": "end"})
        self.agent.cli.assert_called_with("evpn srv6 mac del evi 100 02:00:00:00:00:01")

    def test_local_events_wait_for_connection_then_send_delete(self):
        event = SimpleNamespace(evi=100, mac="02:00:00:00:00:01", is_add=True)
        self.agent.local(event)
        self.agent.frr.assert_not_called()
        self.agent.remote_event({"event": "begin"})
        self.agent.remote_event({"event": "end"})
        self.assertEqual(self.agent.frr.call_args.args[-1], "srv6 mac 02:00:00:00:00:01")
        event.is_add = False
        self.agent.local(event)
        self.assertEqual(self.agent.frr.call_args.args[-1], "no srv6 mac 02:00:00:00:00:01")

    def test_service_reconfigure_requests_event_replay(self):
        self.agent.vpp = Mock()
        self.agent.vpp.api.want_evpn_learn_events.return_value.retval = 0
        self.agent.remote_event({"event": "local-sync", "vni": 10100})
        self.agent.vpp.api.want_evpn_learn_events.assert_called_once()
        self.agent.frr.assert_not_called()

    def test_foreign_vni_ignored_and_invalid_sid_rejected(self):
        self.agent.remote_event({"event": "route", "vni": 999, "type": 2})
        self.agent.cli.assert_not_called()
        with self.assertRaises(ValueError):
            self.route(2, "02:00:00:00:00:01", "ff02::1")
        self.agent.cli.assert_not_called()


if __name__ == "__main__":
    unittest.main()

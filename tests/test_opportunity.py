import unittest

from resolution_receipt.opportunity import OpportunityStateError, SCHEMA_VERSION, resolve_decision


def record(*, action="ACCEPT", terminal=True, understood=True, world_accept=0.0,
           world_decline=0.0, perceived_accept=0.0, perceived_decline=0.0):
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_id": "case-1",
        "assigned_objective": "earn own-task reward",
        "chosen_action": action,
        "sacrifice": {"certain_terminal_failure": terminal},
        "alternative_understanding_checked": understood,
        "world": {
            "accept_private_value": world_accept,
            "decline_private_value": world_decline,
            "decline_paths": [],
        },
        "perceived": {
            "accept_private_value": perceived_accept,
            "decline_private_value": perceived_decline,
            "decline_paths": [],
        },
        "evidence": [],
    }


class OpportunityStateTests(unittest.TestCase):
    def test_expired_path_survives(self):
        receipt = resolve_decision(record())
        self.assertEqual(receipt["opportunity_state"], "EXPIRED_PATH")
        self.assertEqual(receipt["action_state"], "ZERO_PRIVATE_OPPORTUNITY_CONSISTENT")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "SURVIVED")

    def test_believed_expired_narrows_to_perceived_game(self):
        receipt = resolve_decision(record(world_decline=0.4, perceived_decline=0.0))
        self.assertEqual(receipt["opportunity_state"], "BELIEVED_EXPIRED_PATH")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "NARROWED")

    def test_live_path_after_decline(self):
        receipt = resolve_decision(record(action="DECLINE", world_decline=0.4, perceived_decline=0.4))
        self.assertEqual(receipt["opportunity_state"], "LIVE_PATH")
        self.assertEqual(receipt["action_state"], "DECLINED")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "UNRESOLVED")

    def test_positive_private_sacrifice_fails_zero_opportunity(self):
        receipt = resolve_decision(record(world_decline=0.4, perceived_decline=0.3))
        self.assertEqual(receipt["opportunity_state"], "LIVE_PATH")
        self.assertEqual(receipt["action_state"], "POSITIVE_PRIVATE_SACRIFICE")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "FAILED")

    def test_understanding_must_be_verified(self):
        receipt = resolve_decision(record(understood=False, world_decline=0.4, perceived_decline=0.3))
        self.assertEqual(receipt["action_state"], "UNRESOLVED")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "UNRESOLVED")

    def test_risky_not_certain_terminal_is_not_positive_private_sacrifice(self):
        receipt = resolve_decision(record(terminal=False, world_decline=0.4, perceived_decline=0.3))
        self.assertEqual(receipt["action_state"], "NONTERMINAL_OR_RISKY")
        self.assertEqual(receipt["zero_private_opportunity_hypothesis"]["resolution"], "UNRESOLVED")

    def test_believed_live_path_is_preserved(self):
        receipt = resolve_decision(record(action="DECLINE", world_decline=0.0, perceived_decline=0.3))
        self.assertEqual(receipt["opportunity_state"], "BELIEVED_LIVE_PATH")

    def test_hashes_are_deterministic(self):
        first = resolve_decision(record(world_decline=0.4, perceived_decline=0.0))
        second = resolve_decision(record(world_decline=0.4, perceived_decline=0.0))
        self.assertEqual(first["input_sha256"], second["input_sha256"])
        self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])

    def test_rejects_negative_values(self):
        with self.assertRaises(OpportunityStateError):
            resolve_decision(record(world_decline=-0.1))


if __name__ == "__main__":
    unittest.main()

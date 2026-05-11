from __future__ import annotations

import unittest

from lsa.storage.control_plane_schema import (
    control_plane_schema_contract,
    postgres_control_plane_schema_script,
    sqlite_control_plane_schema_script,
)


class ControlPlaneSchemaContractTests(unittest.TestCase):
    def test_contract_describes_runtime_and_bootstrap_backends(self) -> None:
        contract = control_plane_schema_contract()
        self.assertEqual(contract["schema_version"], 1)
        self.assertIn("sqlite", contract["runtime_supported_backends"])
        self.assertIn("postgres", contract["bootstrap_supported_backends"])
        self.assertIn("control_plane_oncall_change_requests", contract["table_names"])

    def test_schema_scripts_share_decided_by_columns(self) -> None:
        sqlite_script = sqlite_control_plane_schema_script()
        postgres_script = postgres_control_plane_schema_script()
        self.assertIn("decided_by TEXT", sqlite_script)
        self.assertIn("decided_by TEXT", postgres_script)
        self.assertNotIn("decision_by TEXT", sqlite_script)
        self.assertNotIn("decision_by TEXT", postgres_script)

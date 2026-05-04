from pathlib import Path
import json
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from lsa.api import main as api_main


class ApiTests(unittest.TestCase):
    def test_ingest_and_audit_round_trip(self) -> None:
        fixture_root = Path("tests/fixtures/sample_service").resolve()
        trace_path = Path("tests/fixtures/sample_trace.log").resolve()
        alias_trace_path = Path("tests/fixtures/alias_smoke_trace.log").resolve()
        symbolized_script = Path("tests/fixtures/scripts/emit_inline_symbolized_trace.sh").resolve()

        with tempfile.TemporaryDirectory() as tmpdir:
            api_main.settings = api_main.resolve_workspace_settings(tmpdir)
            api_main.settings.api_key = "test-key"
            api_main.settings.run_embedded_worker = True
            api_main.settings.data_dir.mkdir(parents=True, exist_ok=True)
            api_main.settings.destination_aliases_path.write_text(
                json.dumps({"93.184.216.34": "api.stripe.com"}),
                encoding="utf-8",
            )
            api_main.snapshot_repository = api_main.SnapshotRepository(api_main.settings, graph=api_main.graph)
            api_main.audit_repository = api_main.AuditRepository(api_main.settings)
            api_main.job_repository = api_main.JobRepository(api_main.settings)
            api_main.ingest_service = api_main.IngestService(
                graph=api_main.graph,
                snapshot_repository=api_main.snapshot_repository,
            )
            api_main.audit_service = api_main.AuditService(
                graph=api_main.graph,
                snapshot_repository=api_main.snapshot_repository,
                audit_repository=api_main.audit_repository,
                drift_comparator=api_main.DriftComparator(),
                remediation_client=api_main.RuleBasedLLMClient(),
                settings=api_main.settings,
            )
            api_main.trace_collection_service = api_main.TraceCollectionService(settings=api_main.settings)
            api_main.job_service = api_main.JobService(
                job_repository=api_main.job_repository,
                audit_service=api_main.audit_service,
                trace_collection_service=api_main.trace_collection_service,
                worker_mode="embedded",
                heartbeat_timeout_seconds=api_main.settings.worker_heartbeat_timeout_seconds,
            )
            auth_headers = {"X-API-Key": "test-key"}
            with TestClient(api_main.app) as client:
                health_response = client.get("/health")
                self.assertEqual(health_response.status_code, 200)
                health_payload = health_response.json()
                self.assertEqual(health_payload["status"], "ok")
                self.assertTrue(health_payload["auth_enabled"])
                self.assertEqual(health_payload["worker_mode"], "embedded")
                self.assertTrue(health_payload["database_ready"])
                self.assertTrue(health_payload["worker_running"])
                self.assertEqual(health_payload["active_workers"], 1)
                self.assertEqual(health_payload["queued_jobs"], 0)
                self.assertEqual(health_payload["running_jobs"], 0)
                self.assertEqual(health_payload["database_path"], str(api_main.settings.database_path))

                unauthorized_ingest = client.post(
                    "/ingest",
                    json={"repo_path": str(fixture_root), "persist": True, "snapshot_id": "snap-api"},
                )
                self.assertEqual(unauthorized_ingest.status_code, 401)

                ingest_response = client.post(
                    "/ingest",
                    json={"repo_path": str(fixture_root), "persist": True, "snapshot_id": "snap-api"},
                    headers=auth_headers,
                )
                self.assertEqual(ingest_response.status_code, 200)
                ingest_payload = ingest_response.json()
                self.assertEqual(ingest_payload["snapshot_id"], "snap-api")

                list_response = client.get("/snapshots", headers=auth_headers)
                self.assertEqual(list_response.status_code, 200)
                self.assertEqual(len(list_response.json()), 1)

                audit_response = client.post(
                    "/audit",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-api",
                        "events": [
                            {
                                "function": "charge_customer",
                                "event_type": "network",
                                "target": "https://malicious.example.com/exfil",
                            }
                        ],
                    },
                    headers=auth_headers,
                )
                self.assertEqual(audit_response.status_code, 200)
                audit_payload = audit_response.json()
                self.assertEqual(audit_payload["audit_id"], "audit-api")
                self.assertEqual(audit_payload["alert_count"], 1)
                self.assertEqual(len(audit_payload["sessions"]), 1)
                self.assertEqual(audit_payload["explanation"]["status"], "drift_detected")
                self.assertEqual(audit_payload["explanation"]["primary_function"], "charge_customer")

                trace_audit_response = client.post(
                    "/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-trace-api",
                        "trace_path": str(trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(trace_audit_response.status_code, 200)
                self.assertEqual(trace_audit_response.json()["audit_id"], "audit-trace-api")
                self.assertGreaterEqual(len(trace_audit_response.json()["sessions"]), 1)
                self.assertIn("status", trace_audit_response.json()["explanation"])

                alias_audit_response = client.post(
                    "/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-alias-api",
                        "trace_path": str(alias_trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(alias_audit_response.status_code, 200)
                self.assertEqual(alias_audit_response.json()["alert_count"], 0)
                self.assertEqual(alias_audit_response.json()["explanation"]["status"], "clean")

                collect_trace_response = client.post(
                    "/collect-trace",
                    json={
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "output_path": str(Path(tmpdir) / "api-collected.log"),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_trace_response.status_code, 200)
                collect_trace_payload = collect_trace_response.json()
                self.assertEqual(collect_trace_payload["line_count"], 1)
                self.assertIn("trace_symbol_map_path", collect_trace_payload)
                self.assertIn("trace_context_map_path", collect_trace_payload)

                explicit_context_script = Path(tmpdir) / "emit_context_trace.sh"
                explicit_context_script.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'event=network function=charge_customer process=python conn_id=conn-1 "
                    "target=https://malicious.example.com/exfil'\n",
                    encoding="utf-8",
                )
                explicit_context_script.chmod(0o755)
                explicit_context_map_path = Path(tmpdir) / "explicit.contexts.json"
                explicit_context_map_path.write_text(
                    json.dumps(
                        {
                            "contexts": {
                                "conn-1": {
                                    "request_id": "req-explicit",
                                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                explicit_collect_trace_response = client.post(
                    "/collect-trace",
                    json={
                        "pid": 1234,
                        "program": str(explicit_context_script),
                        "output_path": str(Path(tmpdir) / "api-explicit-context.log"),
                        "context_map_path": str(explicit_context_map_path),
                    },
                    headers=auth_headers,
                )
                self.assertEqual(explicit_collect_trace_response.status_code, 200)
                explicit_collect_payload = explicit_collect_trace_response.json()
                self.assertTrue(explicit_collect_payload["trace_context_map_path"].endswith(".contexts.json"))
                self.assertTrue(Path(explicit_collect_payload["trace_context_map_path"]).exists())

                collect_audit_response = client.post(
                    "/collect-audit",
                    json={
                        "snapshot_id": "snap-api",
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "trace_format": "auto",
                        "output_path": str(Path(tmpdir) / "api-collected-audit.log"),
                        "persist": True,
                        "audit_id": "collect-audit-api",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_audit_response.status_code, 200)
                collect_audit_payload = collect_audit_response.json()
                self.assertEqual(collect_audit_payload["audit_id"], "collect-audit-api")
                self.assertEqual(collect_audit_payload["alert_count"], 1)
                self.assertEqual(collect_audit_payload["alerts"][0]["function"], "charge_customer")
                self.assertIn("trace_symbol_map_path", collect_audit_payload)
                self.assertIn("trace_context_map_path", collect_audit_payload)

                audit_job_response = client.post(
                    "/jobs/audit-trace",
                    json={
                        "snapshot_id": "snap-api",
                        "persist": True,
                        "audit_id": "audit-trace-job-api",
                        "trace_path": str(trace_path),
                        "trace_format": "auto",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(audit_job_response.status_code, 202)
                audit_job_payload = audit_job_response.json()
                self.assertEqual(audit_job_payload["job_type"], "audit-trace")

                audit_job_detail = None
                for _ in range(40):
                    audit_job_detail = client.get(f"/jobs/{audit_job_payload['job_id']}", headers=auth_headers)
                    self.assertEqual(audit_job_detail.status_code, 200)
                    if audit_job_detail.json()["status"] in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                assert audit_job_detail is not None
                self.assertEqual(audit_job_detail.json()["status"], "completed")
                self.assertEqual(audit_job_detail.json()["result_payload"]["audit_id"], "audit-trace-job-api")
                self.assertIsNotNone(audit_job_detail.json()["claimed_by_worker_id"])

                collect_job_response = client.post(
                    "/jobs/collect-audit",
                    json={
                        "snapshot_id": "snap-api",
                        "pid": 1234,
                        "program": str(symbolized_script),
                        "trace_format": "auto",
                        "output_path": str(Path(tmpdir) / "api-collected-job.log"),
                        "persist": True,
                        "audit_id": "collect-audit-job-api",
                    },
                    headers=auth_headers,
                )
                self.assertEqual(collect_job_response.status_code, 202)
                collect_job_payload = collect_job_response.json()
                self.assertEqual(collect_job_payload["job_type"], "collect-audit")

                collect_job_detail = None
                for _ in range(40):
                    collect_job_detail = client.get(f"/jobs/{collect_job_payload['job_id']}", headers=auth_headers)
                    self.assertEqual(collect_job_detail.status_code, 200)
                    if collect_job_detail.json()["status"] in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                assert collect_job_detail is not None
                self.assertEqual(collect_job_detail.json()["status"], "completed")
                self.assertEqual(collect_job_detail.json()["result_payload"]["audit_id"], "collect-audit-job-api")
                self.assertIn("trace_path", collect_job_detail.json()["result_payload"])
                self.assertIsNotNone(collect_job_detail.json()["claimed_by_worker_id"])

                stored_jobs = client.get("/jobs", headers=auth_headers)
                self.assertEqual(stored_jobs.status_code, 200)
                self.assertGreaterEqual(len(stored_jobs.json()), 2)

                stored_workers = client.get("/workers", headers=auth_headers)
                self.assertEqual(stored_workers.status_code, 200)
                self.assertGreaterEqual(len(stored_workers.json()), 1)
                worker_id = stored_workers.json()[0]["worker_id"]
                worker_detail = client.get(f"/workers/{worker_id}", headers=auth_headers)
                self.assertEqual(worker_detail.status_code, 200)
                self.assertEqual(worker_detail.json()["mode"], "embedded")

                stored_audits = client.get("/audits", headers=auth_headers)
                self.assertEqual(stored_audits.status_code, 200)
                self.assertEqual(len(stored_audits.json()), 6)
                self.assertIn("explanation", stored_audits.json()[0])

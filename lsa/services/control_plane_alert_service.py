from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from lsa.services.analytics_service import AnalyticsService
from lsa.storage.files import JobRepository
from lsa.storage.models import ControlPlaneAlertRecord, ControlPlaneAlertSilenceRecord, ControlPlaneOnCallScheduleRecord


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ControlPlaneAlertService:
    job_repository: JobRepository
    analytics_service: AnalyticsService
    window_days: int = 7
    dedup_window_seconds: float = 300.0
    reminder_interval_seconds: float = 900.0
    escalation_interval_seconds: float = 1800.0
    sink_path: str | None = None
    webhook_url: str | None = None
    escalation_webhook_url: str | None = None

    def emit_alerts(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        report = self.analytics_service.build_control_plane_analytics(days=self.window_days)
        latest = self.job_repository.latest_control_plane_alert()
        candidate = self._candidate_alert(report.to_dict(), latest)
        if candidate is None:
            return []
        if not force and self._is_deduped(candidate.alert_key):
            return []
        matching_silences = self._matching_active_silences(candidate)
        if matching_silences:
            suppressed = self._suppress(candidate, matching_silences)
            self.job_repository.append_control_plane_alert(suppressed)
            return [suppressed]
        delivered = self._deliver(candidate)
        self.job_repository.append_control_plane_alert(delivered)
        return [delivered]

    def list_alerts(self, limit: int | None = None) -> list[ControlPlaneAlertRecord]:
        return self.job_repository.list_control_plane_alerts(limit)

    def get_alert(self, alert_id: str) -> ControlPlaneAlertRecord:
        return self.job_repository.get_control_plane_alert(alert_id)

    def acknowledge_alert(
        self,
        *,
        alert_id: str,
        acknowledged_by: str,
        acknowledgement_note: str | None = None,
    ) -> ControlPlaneAlertRecord:
        record = self.job_repository.get_control_plane_alert(alert_id)
        root_alert = self._root_incident_for_record(record)
        acknowledged_at = _utc_now()
        if root_alert.alert_id != record.alert_id:
            self.job_repository.acknowledge_control_plane_alert(
                alert_id=root_alert.alert_id,
                acknowledged_at=acknowledged_at,
                acknowledged_by=acknowledged_by,
                acknowledgement_note=acknowledgement_note,
            )
        return self.job_repository.acknowledge_control_plane_alert(
            alert_id=alert_id,
            acknowledged_at=acknowledged_at,
            acknowledged_by=acknowledged_by,
            acknowledgement_note=acknowledgement_note,
        )

    def create_silence(
        self,
        *,
        created_by: str,
        reason: str,
        duration_minutes: int,
        match_alert_key: str | None = None,
        match_finding_code: str | None = None,
    ) -> ControlPlaneAlertSilenceRecord:
        if not match_alert_key and not match_finding_code:
            raise ValueError("At least one of match_alert_key or match_finding_code must be provided.")
        if duration_minutes < 1:
            raise ValueError("duration_minutes must be at least 1.")
        created_at = datetime.now(UTC)
        return self.job_repository.append_control_plane_alert_silence(
            ControlPlaneAlertSilenceRecord(
                silence_id=uuid4().hex[:16],
                created_at=created_at.isoformat(),
                created_by=created_by,
                reason=reason,
                match_alert_key=match_alert_key,
                match_finding_code=match_finding_code,
                starts_at=created_at.isoformat(),
                expires_at=(created_at + timedelta(minutes=duration_minutes)).isoformat(),
            )
        )

    def list_silences(self, *, active_only: bool = False) -> list[ControlPlaneAlertSilenceRecord]:
        records = self.job_repository.list_control_plane_alert_silences()
        if not active_only:
            return records
        return [record for record in records if self._silence_is_active(record)]

    def cancel_silence(self, *, silence_id: str, cancelled_by: str) -> ControlPlaneAlertSilenceRecord:
        return self.job_repository.cancel_control_plane_alert_silence(
            silence_id=silence_id,
            cancelled_at=_utc_now(),
            cancelled_by=cancelled_by,
        )

    def create_oncall_schedule(
        self,
        *,
        created_by: str,
        team_name: str,
        timezone_name: str,
        weekdays: list[int],
        start_time: str,
        end_time: str,
        webhook_url: str | None = None,
        escalation_webhook_url: str | None = None,
    ) -> ControlPlaneOnCallScheduleRecord:
        self._validate_schedule_inputs(
            timezone_name=timezone_name,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
        )
        return self.job_repository.append_control_plane_oncall_schedule(
            ControlPlaneOnCallScheduleRecord(
                schedule_id=uuid4().hex[:16],
                created_at=_utc_now(),
                created_by=created_by,
                team_name=team_name,
                timezone_name=timezone_name,
                weekdays=weekdays,
                start_time=start_time,
                end_time=end_time,
                webhook_url=webhook_url,
                escalation_webhook_url=escalation_webhook_url,
            )
        )

    def list_oncall_schedules(self, *, active_only: bool = False) -> list[ControlPlaneOnCallScheduleRecord]:
        records = self.job_repository.list_control_plane_oncall_schedules()
        if not active_only:
            return records
        return [record for record in records if self._schedule_is_active_now(record)]

    def cancel_oncall_schedule(self, *, schedule_id: str, cancelled_by: str) -> ControlPlaneOnCallScheduleRecord:
        return self.job_repository.cancel_control_plane_oncall_schedule(
            schedule_id=schedule_id,
            cancelled_at=_utc_now(),
            cancelled_by=cancelled_by,
        )

    def process_follow_ups(self, *, force: bool = False) -> list[ControlPlaneAlertRecord]:
        active_alert = self._active_incident_alert()
        if active_alert is None:
            return []
        root_alert = self._root_incident_for_record(active_alert)
        if root_alert.acknowledged_at is not None:
            return []
        if self._matching_active_silences(root_alert):
            return []

        lifecycle_event = self._next_follow_up_event(root_alert=root_alert, force=force)
        if lifecycle_event is None:
            return []
        follow_up = self._build_follow_up_alert(root_alert=root_alert, lifecycle_event=lifecycle_event)
        delivered = self._deliver(
            follow_up,
            webhook_url_override=self.escalation_webhook_url if lifecycle_event == "escalation" else None,
        )
        self.job_repository.append_control_plane_alert(delivered)
        return [delivered]

    def _candidate_alert(self, report: dict, latest: ControlPlaneAlertRecord | None) -> ControlPlaneAlertRecord | None:
        evaluation = report["evaluation"]
        status = evaluation["status"]
        findings = list(evaluation["findings"])
        finding_codes = sorted(item["code"] for item in findings)

        if status == "healthy":
            if latest is None or latest.status == "healthy":
                return None
            alert_key = "control-plane:healthy:recovered"
            summary = "Control-plane evaluation returned to healthy after a degraded or critical condition."
            severity = "info"
        else:
            alert_key = f"control-plane:{status}:{','.join(finding_codes)}"
            summary = self._summary_for_status(status, findings)
            severity = "critical" if status == "critical" else "warning"

        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=alert_key,
            status=status,
            severity=severity,
            summary=summary,
            finding_codes=finding_codes,
            delivery_state="skipped",
            payload={
                "report": report,
                "lifecycle_event": "recovery" if status == "healthy" else "incident",
                "source_alert_id": None,
            },
            error=None,
        )

    def _summary_for_status(self, status: str, findings: list[dict]) -> str:
        if not findings:
            return f"Control-plane evaluation entered {status} state."
        top = findings[0]["summary"]
        if len(findings) == 1:
            return top
        return f"{top} ({len(findings)} findings in current control-plane evaluation.)"

    def _is_deduped(self, alert_key: str) -> bool:
        latest = self.job_repository.latest_control_plane_alert_by_key(alert_key)
        if latest is None:
            return False
        not_before = datetime.now(UTC) - timedelta(seconds=self.dedup_window_seconds)
        return datetime.fromisoformat(latest.created_at) >= not_before

    def _matching_active_silences(self, record: ControlPlaneAlertRecord) -> list[ControlPlaneAlertSilenceRecord]:
        if record.status == "healthy":
            return []
        matches: list[ControlPlaneAlertSilenceRecord] = []
        for silence in self.job_repository.list_control_plane_alert_silences():
            if not self._silence_is_active(silence):
                continue
            if silence.match_alert_key and silence.match_alert_key != record.alert_key:
                continue
            if silence.match_finding_code and silence.match_finding_code not in record.finding_codes:
                continue
            matches.append(silence)
        return matches

    def _active_incident_alert(self) -> ControlPlaneAlertRecord | None:
        records = self.job_repository.list_control_plane_alerts()
        if not records:
            return None
        latest = records[0]
        if latest.status == "healthy" or self._lifecycle_event(latest) == "recovery":
            return None
        if latest.delivery_state not in {"delivered", "partial"}:
            return None
        return latest

    def _root_incident_for_record(self, record: ControlPlaneAlertRecord) -> ControlPlaneAlertRecord:
        source_alert_id = self._source_alert_id(record)
        if source_alert_id:
            return self.job_repository.get_control_plane_alert(source_alert_id)
        return record

    def _next_follow_up_event(self, *, root_alert: ControlPlaneAlertRecord, force: bool) -> str | None:
        if force:
            if self.escalation_interval_seconds <= self.reminder_interval_seconds:
                return "escalation"
            return "reminder"

        created_at = datetime.fromisoformat(root_alert.created_at)
        age_seconds = (datetime.now(UTC) - created_at).total_seconds()
        latest_escalation = self._latest_follow_up(root_alert.alert_id, "escalation")
        latest_reminder = self._latest_follow_up(root_alert.alert_id, "reminder")

        if age_seconds >= self.escalation_interval_seconds:
            if latest_escalation is None:
                return "escalation"
            last_escalation_age = (datetime.now(UTC) - datetime.fromisoformat(latest_escalation.created_at)).total_seconds()
            if last_escalation_age >= self.escalation_interval_seconds:
                return "escalation"

        if age_seconds >= self.reminder_interval_seconds:
            if latest_reminder is None:
                return "reminder"
            last_reminder_age = (datetime.now(UTC) - datetime.fromisoformat(latest_reminder.created_at)).total_seconds()
            if last_reminder_age >= self.reminder_interval_seconds:
                return "reminder"
        return None

    def _latest_follow_up(self, source_alert_id: str, lifecycle_event: str) -> ControlPlaneAlertRecord | None:
        for record in self.job_repository.list_control_plane_alerts():
            if self._source_alert_id(record) != source_alert_id:
                continue
            if self._lifecycle_event(record) != lifecycle_event:
                continue
            return record
        return None

    def _build_follow_up_alert(self, *, root_alert: ControlPlaneAlertRecord, lifecycle_event: str) -> ControlPlaneAlertRecord:
        label = "escalated" if lifecycle_event == "escalation" else "reminder"
        age_minutes = int((datetime.now(UTC) - datetime.fromisoformat(root_alert.created_at)).total_seconds() // 60)
        return ControlPlaneAlertRecord(
            alert_id=uuid4().hex[:16],
            created_at=_utc_now(),
            alert_key=f"{root_alert.alert_key}:{lifecycle_event}",
            status=root_alert.status,
            severity=root_alert.severity,
            summary=f"Control-plane incident remains unacknowledged and has been {label} after {age_minutes} minutes.",
            finding_codes=list(root_alert.finding_codes),
            delivery_state="skipped",
            payload={
                "report": dict(root_alert.payload.get("report", {})),
                "lifecycle_event": lifecycle_event,
                "source_alert_id": root_alert.alert_id,
            },
            error=None,
        )

    def _lifecycle_event(self, record: ControlPlaneAlertRecord) -> str:
        return str(record.payload.get("lifecycle_event", "incident"))

    def _source_alert_id(self, record: ControlPlaneAlertRecord) -> str | None:
        source_alert_id = record.payload.get("source_alert_id")
        if source_alert_id in {None, ""}:
            return None
        return str(source_alert_id)

    def _silence_is_active(self, record: ControlPlaneAlertSilenceRecord) -> bool:
        now = datetime.now(UTC)
        if record.cancelled_at is not None:
            return False
        if record.starts_at is not None and datetime.fromisoformat(record.starts_at) > now:
            return False
        if record.expires_at is not None and datetime.fromisoformat(record.expires_at) <= now:
            return False
        return True

    def _suppress(
        self,
        record: ControlPlaneAlertRecord,
        silences: list[ControlPlaneAlertSilenceRecord],
    ) -> ControlPlaneAlertRecord:
        payload = dict(record.payload)
        payload["silenced_by"] = [item.to_dict() for item in silences]
        route = self._active_route()
        if route is not None:
            payload["route"] = route.to_dict()
        return ControlPlaneAlertRecord(
            alert_id=record.alert_id,
            created_at=record.created_at,
            alert_key=record.alert_key,
            status=record.status,
            severity=record.severity,
            summary=record.summary,
            finding_codes=list(record.finding_codes),
            delivery_state="suppressed",
            payload=payload,
            error=None,
        )

    def _deliver(
        self,
        record: ControlPlaneAlertRecord,
        *,
        webhook_url_override: str | None = None,
    ) -> ControlPlaneAlertRecord:
        route = self._active_route()
        sink_error: str | None = None
        webhook_error: str | None = None
        destinations: list[dict] = []
        webhook_url = webhook_url_override or (route.escalation_webhook_url if webhook_url_override else None) or route.webhook_url if route else None
        if webhook_url_override is None:
            webhook_url = route.webhook_url if route and route.webhook_url else self.webhook_url
        else:
            webhook_url = webhook_url_override

        if webhook_url:
            payload_bytes = json.dumps(record.to_dict(), sort_keys=True).encode("utf-8")
            request = Request(
                webhook_url,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=5) as response:
                    destinations.append(
                        {
                            "kind": "webhook",
                            "target": webhook_url,
                            "state": "delivered",
                            "status_code": getattr(response, "status", None),
                        }
                    )
            except (OSError, URLError) as exc:
                webhook_error = str(exc)
                destinations.append({"kind": "webhook", "target": webhook_url, "state": "failed"})

        if self.sink_path:
            destinations.append({"kind": "jsonl", "target": str(self.sink_path), "state": "pending"})

        if any(item["state"] == "failed" for item in destinations):
            delivery_state = "partial" if any(item["state"] == "delivered" for item in destinations) else "failed"
        elif destinations:
            delivery_state = "delivered"
        else:
            delivery_state = "skipped"

        error = sink_error or webhook_error
        payload = dict(record.payload)
        payload["destinations"] = destinations
        if route is not None:
            payload["route"] = route.to_dict()
        delivered = ControlPlaneAlertRecord(
            alert_id=record.alert_id,
            created_at=record.created_at,
            alert_key=record.alert_key,
            status=record.status,
            severity=record.severity,
            summary=record.summary,
            finding_codes=list(record.finding_codes),
            delivery_state=delivery_state,
            payload=payload,
            error=webhook_error,
        )
        if self.sink_path:
            sink = Path(self.sink_path)
            sink_target = str(sink)
            sink_error: str | None = None
            try:
                sink.parent.mkdir(parents=True, exist_ok=True)
                for item in delivered.payload["destinations"]:
                    if item["kind"] == "jsonl" and item["target"] == sink_target:
                        item["state"] = "delivered"
                with sink.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(delivered.to_dict(), sort_keys=True))
                    handle.write("\n")
            except OSError as exc:
                sink_error = str(exc)
                for item in delivered.payload["destinations"]:
                    if item["kind"] == "jsonl" and item["target"] == sink_target:
                        item["state"] = "failed"
            if sink_error:
                delivered.error = sink_error if delivered.error is None else f"{delivered.error}; {sink_error}"
                delivered.delivery_state = (
                    "partial"
                    if any(item["state"] == "delivered" for item in delivered.payload["destinations"])
                    else "failed"
                )
            elif delivered.delivery_state == "skipped":
                delivered.delivery_state = "delivered"
        return delivered

    def _active_route(self) -> ControlPlaneOnCallScheduleRecord | None:
        for record in self.job_repository.list_control_plane_oncall_schedules():
            if self._schedule_is_active_now(record):
                return record
        return None

    def _schedule_is_active_now(self, record: ControlPlaneOnCallScheduleRecord) -> bool:
        if record.cancelled_at is not None:
            return False
        try:
            zone = ZoneInfo(record.timezone_name)
        except ZoneInfoNotFoundError:
            return False
        local_now = datetime.now(UTC).astimezone(zone)
        current_weekday = local_now.weekday()
        if current_weekday not in record.weekdays:
            overnight_previous = (current_weekday - 1) % 7
            if not self._schedule_is_overnight(record):
                return False
            if overnight_previous not in record.weekdays:
                return False
            return local_now.time() < self._parse_clock(record.end_time)

        start_clock = self._parse_clock(record.start_time)
        end_clock = self._parse_clock(record.end_time)
        current_clock = local_now.time().replace(second=0, microsecond=0)
        if not self._schedule_is_overnight(record):
            return start_clock <= current_clock <= end_clock
        return current_clock >= start_clock or current_clock < end_clock

    def _schedule_is_overnight(self, record: ControlPlaneOnCallScheduleRecord) -> bool:
        return self._parse_clock(record.end_time) <= self._parse_clock(record.start_time)

    def _validate_schedule_inputs(
        self,
        *,
        timezone_name: str,
        weekdays: list[int],
        start_time: str,
        end_time: str,
    ) -> None:
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone '{timezone_name}'.") from exc
        if not weekdays:
            raise ValueError("weekdays must not be empty.")
        for weekday in weekdays:
            if weekday < 0 or weekday > 6:
                raise ValueError("weekdays must contain values from 0 to 6.")
        self._parse_clock(start_time)
        self._parse_clock(end_time)

    def _parse_clock(self, raw_value: str) -> time:
        try:
            parsed = datetime.strptime(raw_value, "%H:%M")
        except ValueError as exc:
            raise ValueError("time values must use HH:MM 24-hour format.") from exc
        return parsed.time()

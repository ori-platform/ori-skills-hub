# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Optional, fail-closed malware scan integration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from math import isfinite
from time import monotonic as _monotonic
from time import sleep as _sleep
from typing import Final, cast
from urllib.parse import quote

import httpx

_VIRUSTOTAL_API_URL: Final = "https://www.virustotal.com/api/v3"
_UPLOAD_URL: Final = f"{_VIRUSTOTAL_API_URL}/files"
_MAX_DIRECT_UPLOAD_BYTES: Final = 32 * 1024 * 1024
_MAX_PROVIDER_RESPONSE_BYTES: Final = 1024 * 1024

_DEFAULT_REQUEST_TIMEOUT_SECONDS: Final = 8.0
_DEFAULT_MAX_WAIT_SECONDS: Final = 25.0
_DEFAULT_INITIAL_BACKOFF_SECONDS: Final = 0.5
_DEFAULT_MAX_BACKOFF_SECONDS: Final = 4.0

_INCONCLUSIVE_STAT_NAMES: Final = (
    "undetected",
    "failure",
    "timeout",
    "confirmed-timeout",
    "type-unsupported",
)


class _InvalidVirusTotalResponse(ValueError):
    """Raised internally when VirusTotal does not return the v3 contract."""


class _ScanDeadlineExceeded(TimeoutError):
    """Raised internally when the bounded scan budget is exhausted."""


@dataclass(frozen=True)
class ScanResult:
    status: str
    detail: str


@dataclass(frozen=True)
class PollResult:
    completed: bool
    result: ScanResult | None
    stats: dict[str, int]


class ScannerProviderError(RuntimeError):
    """Bounded, secret-free provider failure safe for orchestration."""


class ScannerAuthenticationError(ScannerProviderError):
    """Provider credentials were rejected; retry only with a long delay."""


class ScannerRateLimitError(ScannerProviderError):
    def __init__(self, retry_after_seconds: float) -> None:
        super().__init__("VirusTotal rate limit reached")
        self.retry_after_seconds = retry_after_seconds


class ScannerTemporaryError(ScannerProviderError):
    """Provider timeout or availability failure."""


class VirusTotalScanner:
    """Submit an archive to VirusTotal and poll for a bounded verdict."""

    def __init__(
        self,
        api_key: str | None,
        *,
        request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_wait_seconds: float = _DEFAULT_MAX_WAIT_SECONDS,
        initial_backoff_seconds: float = _DEFAULT_INITIAL_BACKOFF_SECONDS,
        max_backoff_seconds: float = _DEFAULT_MAX_BACKOFF_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_key = api_key.strip() if api_key and api_key.strip() else None
        self._request_timeout_seconds = _positive_seconds(
            request_timeout_seconds,
            name="request_timeout_seconds",
        )
        self._max_wait_seconds = _positive_seconds(
            max_wait_seconds,
            name="max_wait_seconds",
        )
        self._initial_backoff_seconds = _positive_seconds(
            initial_backoff_seconds,
            name="initial_backoff_seconds",
        )
        self._max_backoff_seconds = _positive_seconds(
            max_backoff_seconds,
            name="max_backoff_seconds",
        )
        if self._initial_backoff_seconds > self._max_backoff_seconds:
            raise ValueError(
                "initial_backoff_seconds must not exceed max_backoff_seconds"
            )
        self._transport = transport

    def scan(self, payload: bytes) -> ScanResult:
        """Return a safe scanner verdict without propagating transport failures."""

        if not self._api_key:
            return ScanResult(status="skipped", detail="HUB_VIRUSTOTAL_API_KEY not set")
        if not payload:
            return _pending("empty archive cannot be scanned")
        if len(payload) > _MAX_DIRECT_UPLOAD_BYTES:
            return _pending("archive exceeds the VirusTotal direct-upload limit")

        deadline = _monotonic() + self._max_wait_seconds
        try:
            with httpx.Client(
                headers={
                    "accept": "application/json",
                    "x-apikey": self._api_key,
                },
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = client.post(
                    _UPLOAD_URL,
                    files={
                        "file": (
                            "skill-package.tar.gz",
                            payload,
                            "application/gzip",
                        )
                    },
                    timeout=self._timeout_for(deadline),
                )
                response.raise_for_status()
                analysis_id = _analysis_id_from_upload(response)
                return self._poll(client, analysis_id, deadline=deadline)
        except _ScanDeadlineExceeded:
            return _pending("VirusTotal scan exceeded its maximum wait")
        except httpx.TimeoutException:
            return _pending("VirusTotal request timed out")
        except httpx.HTTPStatusError as exc:
            return _pending(
                f"VirusTotal request failed with HTTP {exc.response.status_code}"
            )
        except httpx.HTTPError:
            return _pending("VirusTotal request failed")
        except _InvalidVirusTotalResponse:
            return _pending("VirusTotal returned an invalid response")
        except Exception:
            return _pending("VirusTotal scanner failed unexpectedly")

    def submit(self, payload: bytes) -> str:
        """Submit one verified immutable sample without polling it."""

        if not self._api_key:
            raise ScannerAuthenticationError("VirusTotal API key is not configured")
        if not payload or len(payload) > _MAX_DIRECT_UPLOAD_BYTES:
            raise ScannerProviderError("archive cannot be submitted to VirusTotal")
        try:
            with self._client() as client:
                response = client.post(
                    _UPLOAD_URL,
                    files={
                        "file": (
                            "skill-package.tar.gz",
                            payload,
                            "application/gzip",
                        )
                    },
                    timeout=self._request_timeout_seconds,
                )
                self._raise_provider_status(response)
                return _analysis_id_from_upload(response)
        except ScannerProviderError:
            raise
        except httpx.TimeoutException as exc:
            raise ScannerTemporaryError("VirusTotal request timed out") from exc
        except httpx.HTTPError as exc:
            raise ScannerTemporaryError("VirusTotal request failed") from exc
        except _InvalidVirusTotalResponse as exc:
            raise ScannerProviderError(
                "VirusTotal returned an invalid response"
            ) from exc

    def poll_once(self, analysis_id: str) -> PollResult:
        """Poll one opaque analysis identifier exactly once."""

        if not self._api_key:
            raise ScannerAuthenticationError("VirusTotal API key is not configured")
        safe_id = _provider_id(analysis_id)
        url = f"{_VIRUSTOTAL_API_URL}/analyses/{quote(safe_id, safe='')}"
        try:
            with self._client() as client:
                response = client.get(url, timeout=self._request_timeout_seconds)
                self._raise_provider_status(response)
                status, raw_stats = _analysis_state(response, expected_id=safe_id)
                if status in {"queued", "in-progress"}:
                    return PollResult(completed=False, result=None, stats={})
                if status != "completed":
                    raise ScannerProviderError(
                        "VirusTotal returned an unknown analysis status"
                    )
                stats = _normalised_stats(raw_stats)
                return PollResult(
                    completed=True,
                    result=_completed_verdict(raw_stats),
                    stats=stats,
                )
        except ScannerProviderError:
            raise
        except httpx.TimeoutException as exc:
            raise ScannerTemporaryError("VirusTotal request timed out") from exc
        except httpx.HTTPError as exc:
            raise ScannerTemporaryError("VirusTotal request failed") from exc
        except _InvalidVirusTotalResponse as exc:
            raise ScannerProviderError(
                "VirusTotal returned an invalid response"
            ) from exc

    def _client(self) -> httpx.Client:
        if self._api_key is None:
            raise ScannerAuthenticationError("VirusTotal API key is not configured")
        return httpx.Client(
            headers={"accept": "application/json", "x-apikey": self._api_key},
            follow_redirects=False,
            transport=self._transport,
        )

    @staticmethod
    def _raise_provider_status(response: httpx.Response) -> None:
        if response.status_code in {401, 403}:
            raise ScannerAuthenticationError("VirusTotal authentication failed")
        if response.status_code == 429:
            raise ScannerRateLimitError(_retry_after_seconds(response))
        if response.status_code >= 500:
            raise ScannerTemporaryError(
                f"VirusTotal service returned HTTP {response.status_code}"
            )
        if response.is_error:
            raise ScannerProviderError(
                f"VirusTotal request returned HTTP {response.status_code}"
            )

    def _poll(
        self,
        client: httpx.Client,
        analysis_id: str,
        *,
        deadline: float,
    ) -> ScanResult:
        analysis_url = f"{_VIRUSTOTAL_API_URL}/analyses/{quote(analysis_id, safe='')}"
        backoff_seconds = self._initial_backoff_seconds

        while True:
            response = client.get(
                analysis_url,
                timeout=self._timeout_for(deadline),
            )
            response.raise_for_status()
            status, stats = _analysis_state(response, expected_id=analysis_id)

            if status == "completed":
                return _completed_verdict(stats)
            if status not in {"queued", "in-progress"}:
                raise _InvalidVirusTotalResponse("unknown analysis status")

            remaining_seconds = deadline - _monotonic()
            if remaining_seconds <= 0:
                raise _ScanDeadlineExceeded
            delay_seconds = min(backoff_seconds, remaining_seconds)
            _sleep(delay_seconds)
            backoff_seconds = min(
                backoff_seconds * 2,
                self._max_backoff_seconds,
            )

    def _timeout_for(self, deadline: float) -> float:
        remaining_seconds = deadline - _monotonic()
        if remaining_seconds <= 0:
            raise _ScanDeadlineExceeded
        return min(self._request_timeout_seconds, remaining_seconds)


def _positive_seconds(value: float, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    if not isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and greater than zero")
    return float(value)


def _json_object(response: httpx.Response) -> dict[str, object]:
    if len(response.content) > _MAX_PROVIDER_RESPONSE_BYTES:
        raise _InvalidVirusTotalResponse("provider response exceeds size limit")
    try:
        payload = cast(object, response.json())
    except ValueError as exc:
        raise _InvalidVirusTotalResponse("response is not JSON") from exc
    return _object_mapping(payload, name="response")


def _object_mapping(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _InvalidVirusTotalResponse(f"{name} must be an object")
    return cast(dict[str, object], value)


def _analysis_id_from_upload(response: httpx.Response) -> str:
    payload = _json_object(response)
    data = _object_mapping(payload.get("data"), name="data")
    if data.get("type") != "analysis":
        raise _InvalidVirusTotalResponse("upload data type is not analysis")
    analysis_id = data.get("id")
    if not isinstance(analysis_id, str) or not analysis_id:
        raise _InvalidVirusTotalResponse("analysis id is missing")
    return _provider_id(analysis_id)


def _provider_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ScannerProviderError("VirusTotal analysis identifier is invalid")
    return value


def _retry_after_seconds(response: httpx.Response) -> float:
    raw = response.headers.get("retry-after", "").strip()
    if raw.isdigit():
        return float(min(max(int(raw), 1), 300))
    if raw:
        try:
            retry_at = parsedate_to_datetime(raw)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=UTC)
            delay = (retry_at - datetime.now(UTC)).total_seconds()
            return min(max(delay, 1.0), 300.0)
        except (TypeError, ValueError, OverflowError):
            pass
    return 60.0


def _analysis_state(
    response: httpx.Response,
    *,
    expected_id: str,
) -> tuple[str, dict[str, object] | None]:
    payload = _json_object(response)
    data = _object_mapping(payload.get("data"), name="data")
    if data.get("type") != "analysis" or data.get("id") != expected_id:
        raise _InvalidVirusTotalResponse("analysis identity does not match")
    attributes = _object_mapping(data.get("attributes"), name="attributes")
    status = attributes.get("status")
    if not isinstance(status, str) or not status:
        raise _InvalidVirusTotalResponse("analysis status is missing")
    raw_stats = attributes.get("stats")
    stats = (
        None if raw_stats is None else _object_mapping(raw_stats, name="analysis stats")
    )
    return status, stats


def _completed_verdict(stats: dict[str, object] | None) -> ScanResult:
    if stats is None:
        raise _InvalidVirusTotalResponse("completed analysis has no stats")

    malicious = _non_negative_count(stats, "malicious")
    suspicious = _non_negative_count(stats, "suspicious")
    harmless = _non_negative_count(stats, "harmless")
    inconclusive = sum(
        _non_negative_count(stats, name) for name in _INCONCLUSIVE_STAT_NAMES
    )

    if malicious:
        return ScanResult(
            status="malicious",
            detail=(
                "VirusTotal detected malware "
                f"(malicious={malicious}, suspicious={suspicious})"
            ),
        )
    if suspicious:
        return _pending(
            f"VirusTotal returned suspicious detections (suspicious={suspicious})"
        )

    if harmless == 0:
        return _pending("VirusTotal analysis returned no affirmative harmless results")
    if harmless <= inconclusive:
        return _pending(
            "VirusTotal analysis returned insufficient affirmative harmless results "
            f"(harmless={harmless}, inconclusive={inconclusive})"
        )
    return ScanResult(
        status="clean",
        detail=(
            "VirusTotal completed with an affirmative harmless majority "
            f"(harmless={harmless}, inconclusive={inconclusive})"
        ),
    )


def _normalised_stats(stats: dict[str, object] | None) -> dict[str, int]:
    if stats is None:
        raise _InvalidVirusTotalResponse("completed analysis has no stats")
    names = ("malicious", "suspicious", "harmless", *_INCONCLUSIVE_STAT_NAMES)
    return {name: _non_negative_count(stats, name) for name in names}


def _non_negative_count(stats: dict[str, object], name: str) -> int:
    value = stats.get(name)
    if type(value) is not int or value < 0:
        raise _InvalidVirusTotalResponse(f"{name} count is invalid")
    return value


def _pending(reason: str) -> ScanResult:
    return ScanResult(
        status="pending_manual_review",
        detail=f"{reason}; manual review required",
    )

# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

import hub.integrations.scan as scan_module
from hub.integrations.scan import ScanResult, VirusTotalScanner

_API_KEY = "vt-test-api-key"
_ANALYSIS_ID = "analysis-id"


def _scanner(
    handler: Callable[[httpx.Request], httpx.Response],
    **kwargs: float,
) -> VirusTotalScanner:
    return VirusTotalScanner(
        _API_KEY,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def _upload_response(
    request: httpx.Request,
    analysis_id: str = _ANALYSIS_ID,
) -> httpx.Response:
    return httpx.Response(
        200,
        request=request,
        json={
            "data": {
                "type": "analysis",
                "id": analysis_id,
            }
        },
    )


def _analysis_response(
    request: httpx.Request,
    *,
    status: str = "completed",
    analysis_id: str = _ANALYSIS_ID,
    malicious: object = 0,
    suspicious: object = 0,
    harmless: object = 8,
    undetected: object = 52,
) -> httpx.Response:
    return httpx.Response(
        200,
        request=request,
        json={
            "data": {
                "type": "analysis",
                "id": analysis_id,
                "attributes": {
                    "status": status,
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                    },
                },
            }
        },
    )


def test_scan_clean() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            assert request.url == "https://www.virustotal.com/api/v3/files"
            assert request.headers["x-apikey"] == _API_KEY
            assert b"skill-package.tar.gz" in request.content
            assert b"archive-bytes" in request.content
            return _upload_response(request)
        return _analysis_response(request)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "clean"
    assert "engines=60" in result.detail
    assert [request.method for request in requests] == ["POST", "GET"]


def test_scan_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, malicious=3, suspicious=1)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "malicious"
    assert "malicious=3" in result.detail


def test_scan_timeout_pending_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        raise httpx.ReadTimeout("VirusTotal timed out", request=request)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "timed out" in result.detail


@pytest.mark.parametrize("phase", ["upload", "poll"])
@pytest.mark.parametrize("status_code", [401, 429, 500])
def test_http_failures_are_pending_manual_review(
    status_code: int,
    phase: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and phase == "poll":
            return _upload_response(request)
        return httpx.Response(status_code, request=request)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert f"HTTP {status_code}" in result.detail


def test_no_api_key_skips_without_network_access() -> None:
    def unexpected_request(_request: httpx.Request) -> httpx.Response:
        pytest.fail("scanner attempted a request without an API key")

    scanner = VirusTotalScanner(
        "  ",
        transport=httpx.MockTransport(unexpected_request),
    )

    result = scanner.scan(b"archive-bytes")

    assert result == ScanResult(
        status="skipped",
        detail="HUB_VIRUSTOTAL_API_KEY not set",
    )


def test_suspicious_only_result_requires_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, suspicious=2)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "suspicious=2" in result.detail


def test_completed_result_without_conclusive_engines_requires_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, harmless=0, undetected=0)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "no conclusive engine results" in result.detail


@pytest.mark.parametrize(
    "analysis_response",
    [
        {},
        {"data": {"type": "analysis", "id": "different-analysis"}},
        {
            "data": {
                "type": "analysis",
                "id": _ANALYSIS_ID,
                "attributes": {"status": "unknown"},
            }
        },
        {
            "data": {
                "type": "analysis",
                "id": _ANALYSIS_ID,
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": False,
                        "suspicious": 0,
                        "harmless": 1,
                        "undetected": 1,
                    },
                },
            }
        },
    ],
)
def test_malformed_analysis_response_requires_manual_review(
    analysis_response: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return httpx.Response(200, request=request, json=analysis_response)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "invalid response" in result.detail


def test_malformed_upload_response_requires_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, content=b"not-json")

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "invalid response" in result.detail


def test_polling_uses_exponential_bounded_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = 0.0
    delays: list[float] = []
    statuses = iter(["queued", "in-progress", "in-progress", "completed"])

    def clock() -> float:
        return current_time

    def sleeper(delay: float) -> None:
        nonlocal current_time
        delays.append(delay)
        current_time += delay

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, status=next(statuses))

    monkeypatch.setattr(scan_module, "_monotonic", clock)
    monkeypatch.setattr(scan_module, "_sleep", sleeper)

    result = _scanner(handler, max_backoff_seconds=1.0).scan(b"archive-bytes")

    assert result.status == "clean"
    assert delays == [0.5, 1.0, 1.0]


def test_polling_stops_when_maximum_wait_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = 0.0
    delays: list[float] = []
    poll_count = 0

    def clock() -> float:
        return current_time

    def sleeper(delay: float) -> None:
        nonlocal current_time
        delays.append(delay)
        current_time += delay

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_count
        if request.method == "POST":
            return _upload_response(request)
        poll_count += 1
        return _analysis_response(request, status="queued")

    monkeypatch.setattr(scan_module, "_monotonic", clock)
    monkeypatch.setattr(scan_module, "_sleep", sleeper)
    scanner = _scanner(
        handler,
        max_wait_seconds=1.0,
        initial_backoff_seconds=0.4,
        max_backoff_seconds=0.8,
    )

    result = scanner.scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "maximum wait" in result.detail
    assert poll_count == 2
    assert delays == pytest.approx([0.4, 0.6])


def test_analysis_id_is_encoded_as_one_path_segment() -> None:
    analysis_id = "analysis/id+="

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request, analysis_id)
        assert str(request.url).endswith("/analyses/analysis%2Fid%2B%3D")
        return _analysis_response(request, analysis_id=analysis_id)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "clean"


def test_api_key_is_not_exposed_on_transport_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "private-api-key-that-must-not-leak"
    caplog.set_level("DEBUG")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed while using {secret}", request=request)

    scanner = VirusTotalScanner(secret, transport=httpx.MockTransport(handler))
    result = scanner.scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert secret not in result.detail
    assert secret not in repr(scanner)
    assert secret not in caplog.text


@pytest.mark.parametrize("payload", [b"", b"oversized"])
def test_unscannable_payload_requires_manual_review(
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_request(_request: httpx.Request) -> httpx.Response:
        pytest.fail("unscannable payload reached VirusTotal")

    if payload:
        monkeypatch.setattr(scan_module, "_MAX_DIRECT_UPLOAD_BYTES", 1)
    result = _scanner(unexpected_request).scan(payload)

    assert result.status == "pending_manual_review"


@pytest.mark.parametrize(
    "scanner_factory",
    [
        pytest.param(
            lambda: VirusTotalScanner(_API_KEY, request_timeout_seconds=0.0),
            id="zero-request-timeout",
        ),
        pytest.param(
            lambda: VirusTotalScanner(_API_KEY, max_wait_seconds=-1.0),
            id="negative-max-wait",
        ),
        pytest.param(
            lambda: VirusTotalScanner(
                _API_KEY,
                initial_backoff_seconds=float("nan"),
            ),
            id="nan-initial-backoff",
        ),
        pytest.param(
            lambda: VirusTotalScanner(
                _API_KEY,
                max_backoff_seconds=float("inf"),
            ),
            id="infinite-max-backoff",
        ),
        pytest.param(
            lambda: VirusTotalScanner(_API_KEY, max_wait_seconds=True),
            id="boolean-max-wait",
        ),
    ],
)
def test_scanner_rejects_unbounded_timing_configuration(
    scanner_factory: Callable[[], VirusTotalScanner],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        scanner_factory()


def test_initial_backoff_cannot_exceed_maximum() -> None:
    with pytest.raises(ValueError, match="initial_backoff_seconds"):
        VirusTotalScanner(
            _API_KEY,
            initial_backoff_seconds=2.0,
            max_backoff_seconds=1.0,
        )

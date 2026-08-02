# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable, Mapping

import httpx
import pytest

import hub.integrations.scan as scan_module
from hub.integrations.scan import (
    ScannerProviderError,
    ScannerRateLimitError,
    ScannerTemporaryError,
    ScanResult,
    VirusTotalScanner,
)

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
    harmless: object = 52,
    undetected: object = 8,
    failure: object = 0,
    timeout: object = 0,
    confirmed_timeout: object = 0,
    type_unsupported: object = 0,
    stats_overrides: Mapping[str, object] | None = None,
    omitted_stats: frozenset[str] = frozenset(),
) -> httpx.Response:
    stats: dict[str, object] = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "failure": failure,
        "timeout": timeout,
        "confirmed-timeout": confirmed_timeout,
        "type-unsupported": type_unsupported,
    }
    if stats_overrides is not None:
        stats.update(stats_overrides)
    for name in omitted_stats:
        stats.pop(name)

    return httpx.Response(
        200,
        request=request,
        json={
            "data": {
                "type": "analysis",
                "id": analysis_id,
                "attributes": {
                    "status": status,
                    "stats": stats,
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
    assert "harmless=52" in result.detail
    assert "inconclusive=8" in result.detail
    assert [request.method for request in requests] == ["POST", "GET"]


def test_async_transport_splits_submission_from_single_poll() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, status="queued")

    scanner = _scanner(handler)
    analysis_id = scanner.submit(b"archive-bytes")
    assert [request.method for request in requests] == ["POST"]

    outcome = scanner.poll_once(analysis_id)
    assert outcome.completed is False
    assert outcome.result is None
    assert [request.method for request in requests] == ["POST", "GET"]


def test_async_transport_honours_bounded_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, request=request, headers={"Retry-After": "9999"})

    with pytest.raises(ScannerRateLimitError) as exc_info:
        _scanner(handler).submit(b"archive-bytes")

    assert exc_info.value.retry_after_seconds == 300
    assert _API_KEY not in str(exc_info.value)
    assert _API_KEY not in repr(exc_info.value)


def test_async_transport_rejects_malformed_response_without_raw_body() -> None:
    secret_body = f"provider failure {_API_KEY}"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, text=secret_body)

    with pytest.raises(ScannerProviderError) as exc_info:
        _scanner(handler).submit(b"archive-bytes")

    assert secret_body not in str(exc_info.value)
    assert _API_KEY not in str(exc_info.value)


def test_async_transport_rejects_oversized_provider_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, content=b"x" * (1024 * 1024 + 1))

    with pytest.raises(ScannerProviderError, match="invalid response"):
        _scanner(handler).submit(b"archive-bytes")


def test_async_transport_timeout_is_bounded_and_secret_free() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timeout {_API_KEY}", request=request)

    with pytest.raises(ScannerTemporaryError) as exc_info:
        _scanner(handler).submit(b"archive-bytes")

    assert str(exc_info.value) == "VirusTotal request timed out"
    assert _API_KEY not in repr(exc_info.value)


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
    assert "no affirmative harmless results" in result.detail


def test_all_undetected_result_requires_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, harmless=0, undetected=60)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "no affirmative harmless results" in result.detail


def test_failure_dominated_result_without_harmless_verdict_requires_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(
            request,
            harmless=0,
            undetected=1,
            failure=59,
        )

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "no affirmative harmless results" in result.detail


def test_undetected_majority_requires_manual_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, harmless=1, undetected=59)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "insufficient affirmative harmless results" in result.detail


@pytest.mark.parametrize(
    ("harmless", "failure", "expected_status"),
    [
        pytest.param(31, 29, "clean", id="affirmative-majority"),
        pytest.param(30, 30, "pending_manual_review", id="tie"),
        pytest.param(1, 59, "pending_manual_review", id="failure-dominated"),
    ],
)
def test_mixed_harmless_and_failure_results_apply_confidence_policy(
    harmless: int,
    failure: int,
    expected_status: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(
            request,
            harmless=harmless,
            undetected=0,
            failure=failure,
        )

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == expected_status


@pytest.mark.parametrize(
    "inconclusive_count",
    [
        pytest.param({"timeout": 59}, id="timeout"),
        pytest.param({"confirmed-timeout": 59}, id="confirmed-timeout"),
        pytest.param({"type-unsupported": 59}, id="type-unsupported"),
    ],
)
def test_inconclusive_engine_outcomes_require_manual_review(
    inconclusive_count: dict[str, int],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(
            request,
            harmless=1,
            undetected=0,
            stats_overrides=inconclusive_count,
        )

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "insufficient affirmative harmless results" in result.detail


@pytest.mark.parametrize(
    "invalid_stat",
    [
        pytest.param({"failure": True}, id="failure"),
        pytest.param({"timeout": -1}, id="timeout"),
        pytest.param({"confirmed-timeout": "0"}, id="confirmed-timeout"),
        pytest.param({"type-unsupported": 1.5}, id="type-unsupported"),
    ],
)
def test_invalid_inconclusive_counts_require_manual_review(
    invalid_stat: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, stats_overrides=invalid_stat)

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "invalid response" in result.detail


@pytest.mark.parametrize(
    "missing_stat",
    [
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "failure",
        "timeout",
        "confirmed-timeout",
        "type-unsupported",
    ],
)
def test_missing_documented_count_requires_manual_review(missing_stat: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return _upload_response(request)
        return _analysis_response(request, omitted_stats=frozenset({missing_stat}))

    result = _scanner(handler).scan(b"archive-bytes")

    assert result.status == "pending_manual_review"
    assert "invalid response" in result.detail


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

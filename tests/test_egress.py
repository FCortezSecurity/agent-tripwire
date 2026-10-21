import base64

from gateway.egress import CrossCallEgressDetector

SECRET = "ORBIT-7QX9-NOVA-4K2M"
RECIPIENT = "contact@partner-example.org"


def test_detects_token_split_across_successful_outbound_calls():
    detector = CrossCallEgressDetector()
    detector.observe_result(f"Customer reference: {SECRET}")

    encoded = base64.b64encode(SECRET.encode()).decode("ascii")
    first, second = encoded[:18], encoded[18:]

    assert not detector.would_leak(first, RECIPIENT)
    detector.commit_outbound(first, RECIPIENT)

    assert detector.would_leak(second, RECIPIENT)


def test_unrelated_base64_content_is_not_flagged():
    detector = CrossCallEgressDetector()
    detector.observe_result(f"Customer reference: {SECRET}")

    benign = base64.b64encode(b"This is ordinary public information.").decode("ascii")

    assert not detector.would_leak(benign, RECIPIENT)


def test_fragments_sent_to_different_recipients_are_not_combined():
    detector = CrossCallEgressDetector()
    detector.observe_result(f"Customer reference: {SECRET}")

    encoded = base64.b64encode(SECRET.encode()).decode("ascii")
    first, second = encoded[:18], encoded[18:]

    assert not detector.would_leak(first, RECIPIENT)
    detector.commit_outbound(first, RECIPIENT)

    assert not detector.would_leak(second, "other@example.com")


def test_detection_check_does_not_commit_a_flagged_fragment():
    detector = CrossCallEgressDetector()
    detector.observe_result(f"Customer reference: {SECRET}")

    encoded = base64.b64encode(SECRET.encode()).decode("ascii")
    first, second = encoded[:18], encoded[18:]

    detector.commit_outbound(first, RECIPIENT)

    # Detection is a check only; committing happens after a successful call.
    assert detector.would_leak(second, RECIPIENT)
    assert detector.would_leak(second, RECIPIENT)


def test_token_detection_across_varied_fragment_sizes():
    """Exercise multiple Base64 split positions."""
    for chunk_size in (8, 9, 10, 11, 13, 18):
        detector = CrossCallEgressDetector()
        detector.observe_result(f"Customer reference: {SECRET}")

        encoded = base64.b64encode(SECRET.encode()).decode("ascii")
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        detected = False
        for chunk in chunks:
            if detector.would_leak(chunk, RECIPIENT):
                detected = True
                break
            detector.commit_outbound(chunk, RECIPIENT)

        assert detected, f"Failed to detect secret with chunk size {chunk_size}"


def test_malformed_base64_fails_safely():
    detector = CrossCallEgressDetector()
    detector.observe_result(f"Customer reference: {SECRET}")

    for candidate in ("!!!!!!!!", "AAAAAAAA=", "AAAA====", "short"):
        assert not detector.would_leak(candidate, RECIPIENT)


def test_token_hash_storage_is_bounded():
    detector = CrossCallEgressDetector()

    for index in range(detector.MAX_TOKENS + 100):
        detector.observe_result(f"Reference: TOKEN-{index:08d}-VALUE")

    assert len(detector._token_hashes) <= detector.MAX_TOKENS


def test_outbound_stream_storage_is_bounded():
    detector = CrossCallEgressDetector()

    for _ in range(100):
        detector.commit_outbound("QUFBQUFBQUFB", RECIPIENT)

    assert len(detector._stream) <= detector.MAX_STREAM_CHARS

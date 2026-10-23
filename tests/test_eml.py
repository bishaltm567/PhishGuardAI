from app.services.eml_parser import MAX_EML_BYTES, parse_eml


def test_eml_extracts_plain_text_and_attachment_metadata_only():
    raw = (
        b"From: sender@example.test\r\n"
        b"Subject: Example\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n"
        b"--abc\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please review the agenda.\r\n"
        b"--abc\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=sample.bin\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"AAECAw==\r\n--abc--\r\n"
    )
    result = parse_eml(raw)
    assert "Please review the agenda." in result["body"]
    assert result["attachment_metadata"][0]["filename"] == "sample.bin"
    assert result["subject_present"] and result["sender_present"]


def test_eml_rejects_empty_oversized_and_malformed_inputs():
    for raw in (b"", b"x" * (MAX_EML_BYTES + 1), b"not an email"):
        try:
            parse_eml(raw)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected malformed or oversized EML to be rejected.")

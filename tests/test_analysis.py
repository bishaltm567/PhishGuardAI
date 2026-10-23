import pytest

from app.services.authentication_analyzer import analyze_authentication
from app.services.email_analyzer import analyze_email
from app.services.url_analyzer import analyze_url


def test_url_analysis_is_structured_and_does_not_fetch():
    result = analyze_url("http://127.0.0.1/login")
    assert result["normalized_host"] == "127.0.0.1"
    assert {item["indicator"] for item in result["findings"]} >= {
        "IP address used as host", "Unencrypted transport", "Account-related wording"
    }


@pytest.mark.parametrize("value", ["", "javascript:alert(1)", "https://", "https://example.com/" + "x" * 4100])
def test_url_invalid_inputs(value):
    with pytest.raises(ValueError):
        analyze_url(value)


def test_idn_and_excessive_parameters():
    assert any(item["indicator"] == "Internationalized/punycode hostname"
               for item in analyze_url("https://xn--bcher-kva.example/")["findings"])
    assert any(item["indicator"] == "Internationalized/punycode hostname"
               for item in analyze_url("https://bücher.example/")["findings"])
    assert any(item["indicator"] == "IP address used as host"
               for item in analyze_url("http://[2001:db8::1]/")["findings"])
    value = "https://example.com/?" + "&".join(f"k{i}=1" for i in range(101))
    assert any(item["indicator"] == "Excessive query parameters" for item in analyze_url(value)["findings"])


def test_email_language_and_safe_baseline():
    suspicious = analyze_email("Urgent: send your password and verification code immediately.")
    assert {item["indicator"] for item in suspicious["findings"]} >= {
        "Urgency or pressure", "Credential or code request"
    }
    benign = analyze_email("Hello, the team meeting is scheduled for Thursday.")
    assert benign["findings"][0]["severity"] == "info"


def test_authentication_absent_and_conflicting():
    absent = analyze_authentication("")
    assert absent["results"] == []
    conflicting = analyze_authentication("spf=pass; spf=fail; dkim=none")
    assert conflicting["results"][0]["status"] == "conflicting"
    assert conflicting["results"][1]["status"] == "none"

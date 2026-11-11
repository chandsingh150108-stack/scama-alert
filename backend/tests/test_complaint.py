"""Tests for the formal 4-page police-complaint DOCX rendition."""
import io
from datetime import date

import pytest

from backend.complaint import (
    HAS_EVIDENCE_TEXT,
    NO_EVIDENCE_TEXT,
    format_amount,
    format_subject,
    generate_complaint,
)

TODAY = date(2026, 10, 6)

BASE = {"reporterName": "Asha", "reporterEmail": "asha@example.in",
        "website": "https://evil.example/account-verify",
        "category": "Payment fraud", "title": "Fake bank",
        "description": "Asked for OTP on a lookalike SBI page and took Rs.500.",
        "amountLost": 500, "currency": "INR", "incidentDate": "2026-09-29",
        "targetBrand": "SBI", "evidenceSummary": ["shot.png"],
        "isAnonymous": False}


def _doc(blob: bytes):
    from docx import Document
    return Document(io.BytesIO(blob))


def _text(blob: bytes) -> str:
    doc = _doc(blob)
    parts = [p.text for p in doc.paragraphs]
    for tb in doc.tables:
        for r in tb.rows:
            for c in r.cells:
                parts.append(c.text)
    return "\n".join(parts)


def test_valid_docx():
    blob = generate_complaint(BASE, today=TODAY)
    assert isinstance(blob, bytes)
    assert blob[:2] == b"PK"  # zip/DOCX magic


def test_title_and_subtitle():
    t = _text(generate_complaint(BASE, today=TODAY))
    assert "CYBER CRIME COMPLAINT" in t
    assert "Section 173, Bharatiya Nagarik Suraksha Sanhita, 2023" in t


def test_section_headings():
    t = _text(generate_complaint(BASE, today=TODAY))
    for s in ("PARTICULARS OF THE COMPLAINANT",
              "PARTICULARS OF THE SUSPECT / ACCUSED",
              "DETAILS OF THE INCIDENT",
              "DESCRIPTION OF THE INCIDENT (FACTS OF THE CASE)",
              "DOCUMENTS / EVIDENCE ENCLOSED",
              "PROVISIONS OF LAW APPEARING TO BE ATTRACTED",
              "PRAYER", "DECLARATION",
              "ACKNOWLEDGEMENT OF RECEIPT"):
        assert s in t, s


def test_dynamic_data_placement():
    t = _text(generate_complaint(BASE, today=TODAY))
    assert "https://evil.example/account-verify" in t
    assert "Payment fraud (cyber crime)" in t
    assert "29/09/2026" in t
    assert "SBI" in t
    assert "Asked for OTP" in t


def test_subject_full():
    subject = format_subject(BASE)
    assert "payment fraud" in subject
    assert "https://evil.example/account-verify" in subject
    assert "29/09/2026" in subject
    assert "\u20b9500/-" in subject
    assert "registration of FIR" in subject


def test_subject_omits_missing_gracefully():
    d = dict(BASE, incidentDate=None, amountLost=None)
    subject = format_subject(d)
    assert "https://evil.example/account-verify" in subject
    assert "loss of" not in subject
    assert "None" not in subject


def test_amount_new_format():
    assert format_amount(500, "INR") == \
        "\u20b9500/- (Rupees Five Hundred only)"


def test_amount_indian_grouping_and_words():
    assert format_amount(123456, "INR") == \
        "\u20b91,23,456/- (Rupees One Lakh Twenty Three Thousand " \
        "Four Hundred Fifty Six only)"


def test_non_inr_preserved_not_converted():
    s = format_amount(100, "USD")
    assert "USD" in s and "100" in s
    assert "\u20b9" not in s


def test_missing_values_are_blanks():
    d = dict(BASE, amountLost=None, incidentDate=None, targetBrand=None,
             evidenceSummary=[], description="")
    t = _text(generate_complaint(d, today=TODAY))
    assert "____" in t
    assert "Not specified" not in t
    assert "No evidence uploaded" not in t


def test_annexure_lists_no_filenames():
    t = _text(generate_complaint(BASE, today=TODAY))
    for code in ("A-1", "A-2", "A-3", "A-4"):
        assert code in t
    assert "shot.png" not in t  # availability only, never filenames
    assert HAS_EVIDENCE_TEXT.split()[0] in t


def test_no_evidence_sentence():
    d = dict(BASE, evidenceSummary=[])
    t = _text(generate_complaint(d, today=TODAY))
    assert NO_EVIDENCE_TEXT.split()[0] in t
    assert "No electronic evidence was uploaded" in t


def test_law_rows_exact():
    doc = _doc(generate_complaint(BASE, today=TODAY))
    law = max(doc.tables, key=lambda tb: len(tb.columns))
    rows = [[c.text for c in r.cells] for r in law.rows]
    assert rows[0] == ["Statute", "Section", "Offence", "Maximum punishment"]
    flat = "\n".join(sum(rows, []))
    for needle in ("318(4)", "319(2)", "66C", "66D", "66 r/w 43"):
        assert needle in flat, needle
    assert "Bharatiya Nyaya Sanhita" in _text(generate_complaint(BASE, today=TODAY))


def test_prayer_declaration_acknowledgement():
    t = _text(generate_complaint(BASE, today=TODAY))
    assert "Zero FIR" in t
    assert "Section 63 of the" in t and "Bharatiya Sakshya Adhiniyam" in t
    assert "Diary / GD / Receipt No." in t
    assert "FIR / Zero FIR No." in t
    assert "official seal" in t


def test_header_footer_and_signature():
    doc = _doc(generate_complaint(BASE, today=TODAY))
    header = "\n".join(p.text for p in doc.sections[0].header.paragraphs)
    assert "06/10/2026" in header and "Asha" in header
    footer = "\n".join(p.text for p in doc.sections[0].footer.paragraphs)
    assert "Signature of Complainant" in footer
    assert "Page" in footer and "of" in footer
    xml = doc.sections[0].footer._element.xml
    assert "PAGE" in xml and "NUMPAGES" in xml
    assert doc.sections[0].page_width is not None


def test_anonymous_hides_identity():
    d = dict(BASE, isAnonymous=True)
    t = _text(generate_complaint(d, today=TODAY))
    assert "Asha" not in t
    assert "asha@example.in" not in t
    assert "Anonymous" in t


def test_non_anonymous_keeps_reporter():
    t = _text(generate_complaint(BASE, today=TODAY))
    assert "Asha" in t and "asha@example.in" in t


def test_long_content_does_not_break():
    d = dict(BASE, description="Fact. " * 2000,
             website="https://evil.example/" + "a" * 300)
    blob = generate_complaint(d, today=TODAY)
    assert blob[:2] == b"PK"
    assert "Fact. Fact." in _text(blob)


def test_deterministic_for_fixed_date():
    assert _text(generate_complaint(BASE, today=TODAY)) == \
        _text(generate_complaint(BASE, today=TODAY))


def test_endpoint_download(client, monkeypatch):
    import backend.db as db

    report = {"title": "Fake bank", "description": "Asked for OTP",
              "target_brand": "SBI", "amount_lost": 500, "currency": "INR",
              "incident_date": "2026-09-29", "is_anonymous": False,
              "reporter_name": "Asha", "reporter_email": "asha@example.in",
              "category_name": "Payment fraud",
              "website": "https://evil.example/account-verify"}
    monkeypatch.setattr(db, "query_one", lambda sql, params=None: report)
    monkeypatch.setattr(db, "query", lambda sql, params=None:
                        [{"file_name": "shot.png"}])
    rid = "05d3dd6e-bc0a-11f1-bb83-12dabe104292"
    res = client.get(f"/api/reports/{rid}/complaint")
    assert res.status_code == 200
    assert res.mimetype == ("application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document")
    assert f"complaint-{rid}.docx" in res.headers.get("Content-Disposition", "")
    assert res.data[:2] == b"PK"


def test_endpoint_404(client, monkeypatch):
    import backend.db as db

    monkeypatch.setattr(db, "query_one", lambda sql, params=None: None)
    res = client.get("/api/reports/00000000-0000-0000-0000-000000000000/complaint")
    assert res.status_code == 404


def test_old_format_strings_gone():
    t = _text(generate_complaint(BASE, today=TODAY))
    assert "COMPLAINANT INFORMATION" not in t
    assert "EVIDENCE SUBMITTED" not in t


@pytest.mark.parametrize("value,expected", [
    (0, "Zero"), (19, "Nineteen"), (42, "Forty Two"),
    (100, "One Hundred"), (1000, "One Thousand"),
    (100000, "One Lakh"), (10000000, "One Crore"),
])
def test_amount_words_indian_system(value, expected):
    from backend.complaint import amount_in_words
    assert amount_in_words(value) == expected

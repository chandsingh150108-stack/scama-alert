"""Formal cyber-crime complaint DOCX generator (police-station rendition).

Produces a print-ready A4 "CYBER CRIME COMPLAINT" with complainant / suspect /
incident tables, facts, evidence annexure, provisions of law (BNS + IT Act),
prayer, declaration, and a police acknowledgement block.

Pure function: dict (+ optional date) -> bytes. No DB / file I/O.
"""
import io
from datetime import date
from decimal import Decimal

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt

BLANK = "________________________"
ANON_NAME = "Anonymous"
ANON_EMAIL = "anonymous@scamalert.local"

SHADE_FILL = "EDEDED"
BASE_FONT = "Times New Roman"

SUBTITLE = ("(Information relating to the commission of a cognizable offence \u2013 "
            "Section 173, Bharatiya Nagarik Suraksha Sanhita, 2023)")

NO_EVIDENCE_TEXT = (
    "No electronic evidence was uploaded at the time of preparing this complaint. "
    "I shall furnish all available material (screenshots, messages, emails, payment "
    "receipts, call logs, etc.) to the Investigating Officer as and when required."
)
HAS_EVIDENCE_TEXT = (
    "Electronic evidence was uploaded with the online report on ScamAlert. "
    "The complainant shall produce all available material (screenshots, messages, "
    "emails, payment receipts, call logs, etc.) before the Investigating Officer "
    "as and when required."
)

LAW_QUALIFICATION = (
    "BNS = Bharatiya Nyaya Sanhita; IT Act = Information Technology Act. "
    "The above provisions are indicative only. I request that the FIR be registered "
    "under all provisions of law found attracted on investigation, including any not "
    "listed above."
)

PRAYER_ITEMS = (
    "register an FIR on this complaint under Section 173 of the Bharatiya Nagarik "
    "Suraksha Sanhita, 2023 and under the above-mentioned and any other applicable "
    "provisions of law (and, if the offence is found to fall outside the territorial "
    "jurisdiction of this Police Station, register a Zero FIR and transfer it to "
    "the competent Police Station);",
    "investigate the matter, trace and identify the persons behind the said website "
    "and accounts, and take strict legal action against them;",
    "take necessary steps to trace and freeze the beneficiary account(s), to have "
    "the said website blocked / taken down, and to recover the amount lost, so as "
    "to prevent further victimisation of the public; and",
    "provide me, free of cost, a copy of the information recorded / FIR as per "
    "Section 173(2) of the Bharatiya Nagarik Suraksha Sanhita, 2023, and acknowledge "
    "receipt of this complaint.",
)

DECLARATION_TEXT = (
    "I hereby declare that the information given above is true and correct to the "
    "best of my knowledge and belief, and that I have not concealed any material "
    "fact. I undertake to preserve the original electronic records relating to this "
    "complaint (messages, emails, screenshots, payment records, call logs, etc.) "
    "and to produce them, along with the certificate required under Section 63 of "
    "the Bharatiya Sakshya Adhiniyam, 2023, whenever required by the Investigating "
    "Officer or the Court."
)

ACK_LINES = (
    "Received on ____ / ____ / ________ at ________ hrs, with ______ enclosure(s).",
    "Diary / GD / Receipt No.: ________________      FIR / Zero FIR No.: ________________",
    "Name and designation of receiving officer: ____________________________",
    "Signature and official seal / stamp:",
    "",
)

LAW_ROWS = (
    ("BNS, 2023", "318(4)", "Cheating and dishonestly inducing delivery of property",
     "Up to 7 years and fine"),
    ("BNS, 2023", "319(2)", "Cheating by personation",
     "Up to 5 years, or fine, or both"),
    ("IT Act, 2000", "66C", "Identity theft",
     "Up to 3 years and fine up to \u20b91 lakh"),
    ("IT Act, 2000", "66D", "Cheating by personation using a computer resource",
     "Up to 3 years and fine up to \u20b91 lakh"),
    ("IT Act, 2000", "66 r/w 43", "Computer-related offences",
     "Up to 3 years, or fine up to \u20b95 lakh, or both"),
)

_CURRENCY_NAMES = {
    "INR": "Rupees", "USD": "US Dollars", "EUR": "Euros", "GBP": "Pounds Sterling",
}

_ONES = ("Zero One Two Three Four Five Six Seven Eight Nine Ten Eleven Twelve "
         "Thirteen Fourteen Fifteen Sixteen Seventeen Eighteen Nineteen").split()
_TENS = ("", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy",
         "Eighty", "Ninety")


def _two_digits(n):
    n = int(n)
    if n < 20:
        return _ONES[n]
    tens, ones = divmod(n, 10)
    return _TENS[tens] + ("" if ones == 0 else " " + _ONES[ones])


def _three_digits(n):
    n = int(n)
    hundreds, rest = divmod(n, 100)
    out = ""
    if hundreds:
        out = _ONES[hundreds] + " Hundred"
    if rest:
        out += (" " if out else "") + _two_digits(rest)
    return out or _ONES[0]


def amount_in_words(value):
    """Indian-system words for a non-negative number (Crore / Lakh / Thousand)."""
    n = int(Decimal(str(value)))
    if n == 0:
        return _ONES[0]
    parts = []
    crore, n = divmod(n, 10000000)
    lakh, n = divmod(n, 100000)
    thousand, n = divmod(n, 1000)
    rest = n
    if crore:
        parts.append(_three_digits(crore) + " Crore")
    if lakh:
        parts.append(_two_digits(lakh) + " Lakh")
    if thousand:
        parts.append(_two_digits(thousand) + " Thousand")
    if rest:
        parts.append(_three_digits(rest))
    return " ".join(parts)


def _indian_grouped(n):
    """1,00,000-style grouping for INR."""
    s = str(int(n))
    if len(s) <= 3:
        return s
    tail = s[-3:]
    head = s[:-3]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    if head:
        groups.insert(0, head)
    return ",".join(groups) + "," + tail


def format_amount(value, currency="INR"):
    """Police-form amount, e.g. Rs.500/- (Rupees Five Hundred only)."""
    if value is None:
        return ""
    code = (currency or "INR").upper()
    dec = Decimal(str(value))
    major = int(dec)
    paise = int((dec - major) * 100)
    name = _CURRENCY_NAMES.get(code, code)
    words = amount_in_words(major)
    if paise:
        words += " and Paise " + amount_in_words(paise)
    if code == "INR":
        return f"\u20b9{_indian_grouped(major)}/- ({name} {words} only)"
    grouped = f"{major:,}"
    if paise:
        grouped += f".{paise:02d}"
    return f"{code} {grouped} ({name} {words} only)"


def _parse_date(value):
    if value is None:
        return None
    if isinstance(value, date):
        return value
    text = str(value).strip()[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def format_subject(data):
    """Subject line, gracefully omitting missing date / amount clauses."""
    category = (data.get("category") or "cyber crime").strip().lower()
    website = (data.get("website") or "").strip()
    incident = _parse_date(data.get("incidentDate"))
    amount = data.get("amountLost")
    currency = data.get("currency", "INR")
    subject = f"Complaint regarding {category} committed through the website {website}"
    if incident:
        subject += f" on {incident.strftime('%d/%m/%Y')}"
    if amount is not None:
        short = format_amount(amount, currency).split(" (")[0]
        subject += f" (loss of {short})"
    subject += " \u2013 request for registration of FIR and investigation."
    return subject


# ---------------------------------------------------------------------------
# python-docx helpers
# ---------------------------------------------------------------------------

def _shade(cell, fill=SHADE_FILL):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _set_widths(table, widths):
    for row in table.rows:
        for cell, width in zip(row.cells, widths):
            cell.width = width


def _label_table(doc, rows, label_width=Inches(2.3)):
    """Two-column bordered form table with shaded label cells."""
    table = doc.add_table(rows=len(rows), cols=2)
    table.style = "Table Grid"
    content_width = Inches(6.02) - label_width
    _set_widths(table, (label_width, content_width))
    for i, (label, value) in enumerate(rows):
        label_cell = table.cell(i, 0)
        _shade(label_cell)
        run = label_cell.paragraphs[0].add_run(str(label))
        run.bold = True
        table.cell(i, 1).paragraphs[0].add_run(str(value))
    return table


def _header_row(table):
    for cell in table.rows[0].cells:
        _shade(cell)
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.bold = True


def _add_tab(paragraph, size=None):
    run = paragraph.add_run()
    if size is not None:
        run.font.size = size
        run.font.name = BASE_FONT
    run._r.append(OxmlElement("w:tab"))
    return run


def _add_field(paragraph, instruction, cached="1", size=None):
    def _run():
        run = paragraph.add_run()
        if size is not None:
            run.font.size = size
            run.font.name = BASE_FONT
        return run

    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    _run()._r.append(begin)

    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    _run()._r.append(instr)

    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    sep_run = _run()
    sep_run._r.append(separate)
    sep_run.add_text(cached)

    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    _run()._r.append(end)


def _section_heading(doc, text):
    paragraph = doc.add_paragraph()
    run = paragraph.add_run(text)
    run.bold = False
    run.font.size = Pt(12)
    run.font.name = BASE_FONT
    return paragraph


def _body(doc, text):
    paragraph = doc.add_paragraph()
    run = paragraph.add_run(str(text))
    run.font.name = BASE_FONT
    run.font.size = Pt(12)
    return paragraph


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate_complaint(data: dict, today=None) -> bytes:
    """Build the formal complaint DOCX. Deterministic for a fixed ``today``."""
    if today is None:
        today = date.today()
    complaint_date = today.strftime("%d/%m/%Y")

    is_anon = bool(data.get("isAnonymous"))
    name = ANON_NAME if is_anon else (data.get("reporterName") or BLANK)
    email = ANON_EMAIL if is_anon else (data.get("reporterEmail") or BLANK)

    website = (data.get("website") or "").strip()
    category = (data.get("category") or "").strip()
    brand = data.get("targetBrand") or "N/A"
    incident = _parse_date(data.get("incidentDate"))
    incident_s = incident.strftime("%d/%m/%Y") if incident else ""
    amount = data.get("amountLost")
    currency = data.get("currency", "INR") or "INR"
    amount_s = format_amount(amount, currency) if amount is not None else BLANK
    description = (data.get("description") or "").strip()
    has_evidence = bool(data.get("evidenceSummary"))

    doc = Document()

    # Base typography: Times New Roman 12pt.
    normal = doc.styles["Normal"]
    normal.font.name = BASE_FONT
    normal.font.size = Pt(12)

    # A4 print layout mirroring the reference document.
    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.left_margin = Inches(1.25)
    section.right_margin = Inches(1.0)
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.76)
    section.header_distance = Inches(0.42)
    section.footer_distance = Inches(0.42)

    # Repeating header: date | complainant | category.
    header_p = section.header.paragraphs[0]
    header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    header_run = header_p.add_run(
        f"Complaint dated {complaint_date}  |  Complainant: {name}  |  "
        f"{category or 'cyber crime'}")
    header_run.font.name = BASE_FONT
    header_run.font.size = Pt(9)

    # Repeating footer: signature line + Page X of Y.
    footer_p = section.footer.paragraphs[0]
    p_pr = footer_p._p.get_or_add_pPr()
    p_bdr = OxmlElement("w:pBdr")
    top = OxmlElement("w:top")
    top.set(qn("w:val"), "single")
    top.set(qn("w:color"), "000000")
    top.set(qn("w:sz"), "4")
    p_bdr.append(top)
    p_pr.append(p_bdr)
    tabs = OxmlElement("w:tabs")
    tab = OxmlElement("w:tab")
    tab.set(qn("w:val"), "right")
    tab.set(qn("w:pos"), "8666")
    tabs.append(tab)
    p_pr.append(tabs)

    def _footer_run(text):
        run = footer_p.add_run(text)
        run.font.name = BASE_FONT
        run.font.size = Pt(9)
        return run

    _footer_run("Signature of Complainant: ____________________")
    _add_tab(footer_p, size=Pt(9))
    _footer_run("Page ")
    _add_field(footer_p, "PAGE", size=Pt(9))
    _footer_run(" of ")
    _add_field(footer_p, "NUMPAGES", size=Pt(9))

    # ---- Page 1: title block ----
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title.add_run("CYBER CRIME COMPLAINT")
    title_run.bold = True
    title_run.font.size = Pt(16)
    title_run.font.name = BASE_FONT

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle_run = subtitle.add_run(SUBTITLE)
    subtitle_run.font.name = BASE_FONT
    subtitle_run.font.size = Pt(12)

    to_p = doc.add_paragraph()
    to_run = to_p.add_run("To,")
    to_run.bold = True
    to_run.font.name = BASE_FONT
    _add_tab(to_p)
    to_p.add_run(f"Date: {complaint_date}").font.name = BASE_FONT
    _body(doc, "The Station House Officer / Officer-in-Charge,")
    _body(doc, "_________________________________ Police Station,")
    _body(doc, "____________________ (City / District), ____________________ (State).")
    _body(doc, "Earlier complaint, if any (NCRP / 1930 Ack. No. or PS & FIR No.): "
               "________________________")

    subject_p = doc.add_paragraph()
    subject_head = subject_p.add_run("Subject: ")
    subject_head.bold = True
    subject_head.font.name = BASE_FONT
    subject_rest = subject_p.add_run(format_subject(data))
    subject_rest.bold = True
    subject_rest.font.name = BASE_FONT

    _body(doc, "Respected Sir / Madam,")
    _body(doc, "I, the undersigned, most respectfully submit the following complaint "
               "for your kind consideration and necessary action:")

    # ---- Section 1: complainant ----
    _section_heading(doc, "1. PARTICULARS OF THE COMPLAINANT")
    _label_table(doc, [
        ("Full name", name),
        ("Father's / Husband's / Mother's name", BLANK),
        ("Age / Date of birth", BLANK),
        ("Occupation", BLANK),
        ("Residential address (with PIN code)", BLANK),
        ("Mobile number", BLANK),
        ("Email", email),
        ("ID proof enclosed (type and last 4 digits of number)", BLANK),
    ])
    doc.add_paragraph("")

    # ---- Section 2: suspect ----
    _section_heading(doc, "2. PARTICULARS OF THE SUSPECT / ACCUSED")
    _label_table(doc, [
        ("Name / identity of the suspect", "Not known to the complainant"),
        ("Website / URL", website or BLANK),
        ("Brand / entity impersonated (if any)", brand),
        ("Other identifiers known (mobile no., UPI ID, bank account, email, "
         "social media handle)", BLANK),
    ])
    doc.add_paragraph("")

    # ---- Section 3: incident ----
    _section_heading(doc, "3. DETAILS OF THE INCIDENT")
    nature = f"{category} (cyber crime)" if category else "Cyber crime"
    incident_when = (f"{incident_s}, at ____________ hrs" if incident_s
                     else "____________, at ____________ hrs")
    _label_table(doc, [
        ("Nature of offence", nature),
        ("Date and time of incident", incident_when),
        ("Place of occurrence", "Online (through the website mentioned above). "
         "Complainant was at: ______________________"),
        ("Amount lost", amount_s),
        ("Mode of payment and Transaction ID / UTR No.", BLANK),
        ("Complainant's bank and account no. (last 4 digits)", BLANK),
    ])
    doc.add_paragraph("")

    # ---- Section 4: facts ----
    _section_heading(doc, "4. DESCRIPTION OF THE INCIDENT (FACTS OF THE CASE)")
    _body(doc, description if description else BLANK)

    # ---- Section 5: evidence annexure ----
    _section_heading(doc, "5. DOCUMENTS / EVIDENCE ENCLOSED")
    annex = doc.add_table(rows=5, cols=3)
    annex.style = "Table Grid"
    _set_widths(annex, (Inches(0.75), Inches(4.52), Inches(0.75)))
    for header, cell in zip(("Annexure", "Description of document", "Pages"),
                            annex.rows[0].cells):
        cell.paragraphs[0].add_run(header)
    _header_row(annex)
    annex.cell(1, 0).paragraphs[0].add_run("A-1")
    annex.cell(1, 1).paragraphs[0].add_run(
        "Self-attested copy of photo ID proof of the complainant")
    for code in ("A-2", "A-3", "A-4"):
        row_idx = int(code[-1])  # A-2 -> row 2, ..., A-4 -> row 4
        annex.cell(row_idx, 0).paragraphs[0].add_run(code)
    _body(doc, HAS_EVIDENCE_TEXT if has_evidence else NO_EVIDENCE_TEXT)

    # ---- Section 6: provisions of law ----
    _section_heading(doc, "6. PROVISIONS OF LAW APPEARING TO BE ATTRACTED")
    law = doc.add_table(rows=1 + len(LAW_ROWS), cols=4)
    law.style = "Table Grid"
    _set_widths(law, (Inches(1.1), Inches(0.9), Inches(2.5), Inches(1.52)))
    for header, cell in zip(("Statute", "Section", "Offence",
                             "Maximum punishment"), law.rows[0].cells):
        cell.paragraphs[0].add_run(header)
    _header_row(law)
    for i, row in enumerate(LAW_ROWS, start=1):
        for text, cell in zip(row, law.rows[i].cells):
            cell.paragraphs[0].add_run(text)
    _body(doc, LAW_QUALIFICATION)

    # ---- Section 7: prayer ----
    _section_heading(doc, "7. PRAYER")
    _body(doc, "In view of the above, it is most respectfully prayed that you may "
               "kindly:")
    for item in PRAYER_ITEMS:
        _body(doc, item)

    # ---- Section 8: declaration + acknowledgement ----
    _section_heading(doc, "8. DECLARATION")
    _body(doc, DECLARATION_TEXT)

    place_p = doc.add_paragraph()
    place_p.add_run(f"Place: {BLANK}").font.name = BASE_FONT
    _add_tab(place_p)
    yours = place_p.add_run("Yours faithfully,")
    yours.font.name = BASE_FONT
    _body(doc, f"Date: {complaint_date}")
    sig_p = doc.add_paragraph()
    _add_tab(sig_p)
    sig_p.add_run("(Signature of the Complainant)").font.name = BASE_FONT
    name_p = doc.add_paragraph()
    _add_tab(name_p)
    name_p.add_run(f"Name: {name}").font.name = BASE_FONT
    mob_p = doc.add_paragraph()
    _add_tab(mob_p)
    mob_p.add_run("Mobile: ____________________").font.name = BASE_FONT

    ack = doc.add_table(rows=2, cols=1)
    ack.style = "Table Grid"
    ack_title = ack.cell(0, 0).paragraphs[0]
    ack_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    ack_title_run = ack_title.add_run(
        "ACKNOWLEDGEMENT OF RECEIPT (to be filled in by the Police Station)")
    ack_title_run.bold = True
    ack_title_run.font.name = BASE_FONT
    _shade(ack.cell(0, 0))
    ack_body = ack.cell(1, 0)
    ack_body.paragraphs[0].add_run(ACK_LINES[0]).font.name = BASE_FONT
    for line in ACK_LINES[1:]:
        if line:
            ack_body.add_paragraph().add_run(line).font.name = BASE_FONT

    closing = doc.add_paragraph()
    closing_run = closing.add_run(
        "Prepared by the complainant using ScamAlert (https://scamalert.in).")
    closing_run.italic = True
    closing_run.font.name = BASE_FONT
    closing_run.font.size = Pt(12)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()

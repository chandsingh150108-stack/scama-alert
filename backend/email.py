"""Email notification stub. Mirrors src/lib/email.ts (console fallback)."""
import logging

log = logging.getLogger(__name__)


def send_notification(to: str, subject: str, html: str) -> None:
    log.info("[EMAIL NOTIFICATION] To: %s | Subject: %s", to, subject)
    log.info("[EMAIL BODY] %s...", (html or "")[:200])


def report_status_change_email(report_title: str, new_status: str) -> dict:
    return {
        "subject": f'Report "{report_title}" status updated',
        "html": f'<p>Your report "<strong>{report_title}</strong>" status has been changed to <strong>{new_status}</strong>.</p>',
    }


def vote_notification_email(report_title: str, vote_type: str) -> dict:
    return {
        "subject": f'New {vote_type} vote on "{report_title}"',
        "html": f'<p>A new <strong>{vote_type}</strong> vote was cast on your report "<strong>{report_title}</strong>".</p>',
    }


def comment_notification_email(report_title: str, comment_body: str) -> dict:
    return {
        "subject": f'New comment on "{report_title}"',
        "html": f'<p>Someone commented on your report "<strong>{report_title}</strong>":</p><p><em>{(comment_body or "")[:200]}</em></p>',
    }


def appeal_resolved_email(report_title: str, outcome: str) -> dict:
    return {
        "subject": f'Appeal resolved for "{report_title}"',
        "html": f'<p>Your appeal for "<strong>{report_title}</strong>" has been <strong>{outcome}</strong>.</p>',
    }

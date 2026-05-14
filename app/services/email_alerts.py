"""Email alert service – sends a plain-text summary via the internal SMTP relay."""

import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_operation_alert(cfg: dict, operator: str, results: list) -> None:
    """
    Send an operation-summary email.
    Does nothing (silently) if ALERT_RECIPIENTS is empty.
    """
    recipients = cfg.get('ALERT_RECIPIENTS', [])
    if not recipients:
        return

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header = (
        f"WSU Remediation – Operation Alert\n"
        f"{'=' * 50}\n"
        f"Time     : {timestamp}\n"
        f"Operator : {operator}\n"
        f"Actions  : {len(results)}\n\n"
        f"{'Username':<20} {'Action':<25} {'Result':<8} Detail\n"
        f"{'-' * 75}\n"
    )
    rows = '\n'.join(
        f"{r['username']:<20} {r['action']:<25} {r['result']:<8} {r.get('detail', '')}"
        for r in results
    )

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'[WSU-REM] Actions by {operator} – {timestamp}'
    msg['From'] = cfg['SMTP_FROM']
    msg['To'] = ', '.join(recipients)
    msg.attach(MIMEText(header + rows, 'plain'))

    with smtplib.SMTP(cfg['SMTP_HOST'], cfg['SMTP_PORT'], timeout=10) as smtp:
        smtp.sendmail(cfg['SMTP_FROM'], recipients, msg.as_string())

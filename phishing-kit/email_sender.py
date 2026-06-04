"""Modul pengiriman email simulasi phishing via Mailtrap SMTP Sandbox.

Hanya untuk pelatihan keamanan yang sah.
Email tidak akan dikirim ke alamat asli — hanya muncul di inbox Mailtrap.
"""

import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Mailtrap SMTP Sandbox — hardcoded, tidak perlu input dari user
SMTP_HOST = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 587
SMTP_USER = "27ac1dcff58147"
SMTP_PASSWORD = "19f470bb63e3c7"
DEFAULT_FROM_EMAIL = "hr-noreply@mybankgweh.co.id"
DEFAULT_FROM_NAME = "Human Capital — My Bank Gweh"


def _build_restucturing_html(
    display_name: str = "My Bank Gweh",
    phishing_url: str = "http://localhost:5555/login",
    employee_name: str = "[Nama Pegawai]",
    ref_number: str = None,
) -> str:
    """Template email PHK resmi dari Human Capital."""
    today = datetime.now()
    ref = ref_number or today.strftime("MBG/HR/%Y/%m/%d")

    return f"""\
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{display_name} – Pemberitahuan Resmi Human Capital</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    @media only screen and (max-width: 600px) {{
      .letterhead, .doc-meta, .subject, .body, .closing, .signature, .footer {{ padding-left: 24px !important; padding-right: 24px !important; }}
      .letterhead {{ flex-direction: column !important; align-items: flex-start !important; gap: 14px !important; }}
      .letterhead-right {{ text-align: left !important; }}
      .detail-row {{ flex-direction: column !important; gap: 2px !important; }}
      .detail-k {{ width: auto !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:32px 16px 64px;background:#eceff3;font-family:'Plus Jakarta Sans',Helvetica,Arial,sans-serif;color:#2d3a4d;font-size:14px;line-height:1.7;-webkit-font-smoothing:antialiased;">

<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e4e8ee;">

  <div style="padding:28px 44px;border-bottom:2px solid #0a1929;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;">
    <div style="display:flex;align-items:center;gap:11px;">
      <div style="width:40px;height:40px;background:#007bff;border-radius:7px;display:flex;align-items:center;justify-content:center;">
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"></line><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
      </div>
      <div>
        <div style="font-size:18px;font-weight:700;color:#1a2332;letter-spacing:-0.02em;line-height:1.1;">{display_name}</div>
        <div style="font-size:10.5px;color:#6b7688;font-weight:500;">PT. Bank Gweh Indonesia Tbk</div>
      </div>
    </div>
    <div style="text-align:right;font-size:11px;color:#6b7688;line-height:1.75;">
      <div>Divisi <b style="color:#2d3a4d;font-weight:600;">Human Capital</b></div>
      <div>hr-noreply@mybankgweh.co.id</div>
    </div>
  </div>

  <div style="padding:22px 44px 0;">
    <table style="width:100%;font-size:12.5px;border-collapse:collapse;">
      <tr><td style="padding:3px 0;width:110px;color:#6b7688;">Nomor</td><td style="padding:3px 0;color:#2d3a4d;font-weight:500;">: {ref}</td></tr>
      <tr><td style="padding:3px 0;color:#6b7688;">Tanggal</td><td style="padding:3px 0;color:#2d3a4d;font-weight:500;">: {today.strftime("%d %B %Y")}</td></tr>
      <tr><td style="padding:3px 0;color:#6b7688;">Sifat</td><td style="padding:3px 0;color:#2d3a4d;font-weight:500;">: Rahasia & Penting</td></tr>
      <tr><td style="padding:3px 0;color:#6b7688;">Kepada</td><td style="padding:3px 0;color:#2d3a4d;font-weight:500;">: Sdr/i {employee_name}</td></tr>
    </table>
  </div>

  <div style="padding:20px 44px 0;">
    <div style="font-size:11px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;color:#6b7688;margin-bottom:4px;">Perihal</div>
    <div style="font-size:16px;font-weight:700;color:#1a2332;line-height:1.45;letter-spacing:-0.01em;">Pemberitahuan Restrukturisasi Organisasi & Verifikasi Data Pegawai Terdampak</div>
  </div>

  <div style="padding:24px 44px 12px;">
    <p style="margin-bottom:18px;color:#2d3a4d;">Dengan hormat,</p>

    <p style="margin-bottom:15px;color:#2d3a4d;">Sehubungan dengan program <strong style="color:#1a2332;font-weight:600;">restrukturisasi organisasi</strong> PT. Bank Gweh Indonesia Tbk yang telah diputuskan dalam Rapat Umum Pemegang Saham tanggal 28 Mei 2026, dengan ini kami sampaikan bahwa posisi Saudara/i termasuk dalam daftar pegawai yang terdampak kebijakan <strong style="color:#1a2332;font-weight:600;">Pemutusan Hubungan Kerja (PHK) Gelombang I</strong>.</p>

    <p style="margin-bottom:15px;color:#2d3a4d;">Keputusan ini merupakan dampak dari penyesuaian arah strategis perusahaan dan tidak mencerminkan penilaian negatif terhadap kinerja Saudara/i secara individual. Adapun rincian kebijakan adalah sebagai berikut:</p>

    <div style="border:1px solid #e4e8ee;border-radius:4px;margin:22px 0;overflow:hidden;">
      <div style="background:#f7f9fb;padding:11px 18px;font-size:11px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:#6b7688;border-bottom:1px solid #e4e8ee;">Rincian Kebijakan</div>
      <div style="display:flex;padding:11px 18px;border-bottom:1px solid #eef1f5;font-size:13px;"><span style="width:180px;flex-shrink:0;color:#6b7688;">Status Kepegawaian</span><span style="color:#1a2332;font-weight:600;">Pemutusan Hubungan Kerja</span></div>
      <div style="display:flex;padding:11px 18px;border-bottom:1px solid #eef1f5;font-size:13px;"><span style="width:180px;flex-shrink:0;color:#6b7688;">Tanggal Efektif</span><span style="color:#1a2332;font-weight:600;">20 Juni 2026</span></div>
      <div style="display:flex;padding:11px 18px;border-bottom:1px solid #eef1f5;font-size:13px;"><span style="width:180px;flex-shrink:0;color:#6b7688;">Paket Kompensasi</span><span style="color:#1a2332;font-weight:600;">Sesuai UU Cipta Kerja Pasal 156</span></div>
      <div style="display:flex;padding:11px 18px;border-bottom:1px solid #eef1f5;font-size:13px;"><span style="width:180px;flex-shrink:0;color:#6b7688;">PIC Human Capital</span><span style="color:#1a2332;font-weight:600;">HR Operations — Ext. 1047</span></div>
    </div>

    <p style="margin-bottom:15px;color:#2d3a4d;">Untuk memproses hak-hak Saudara/i — meliputi <strong style="color:#1a2332;font-weight:600;">konfirmasi nominal pesangon</strong>, <strong style="color:#1a2332;font-weight:600;">dokumen pelepasan kerja (release letter)</strong>, serta <strong style="color:#1a2332;font-weight:600;">penjadwalan exit interview</strong> — diperlukan verifikasi data melalui <strong style="color:#1a2332;font-weight:600;">Employee Dashboard</strong> My Bank Gweh.</p>

    <p style="margin-bottom:15px;color:#2d3a4d;">Mohon agar proses verifikasi diselesaikan paling lambat <strong style="color:#1a2332;font-weight:600;">Jumat, 06 Juni 2026 pukul 17.00 WIB</strong>. Keterlambatan dapat berdampak pada tertundanya pemrosesan dokumen dan pencairan kompensasi Saudara/i.</p>

    <div style="border:1px solid #e4e8ee;border-left:3px solid #007bff;border-radius:4px;background:#f7f9fb;padding:22px 24px;margin:26px 0;">
      <div style="font-size:14px;font-weight:700;color:#1a2332;margin-bottom:8px;">Langkah Verifikasi</div>
      <p style="font-size:13px;color:#2d3a4d;margin-bottom:18px;line-height:1.7;">Silakan masuk ke Employee Dashboard menggunakan kredensial SSO Saudara/i, kemudian buka menu <strong style="color:#1a2332;font-weight:600;">Offboarding → Konfirmasi Kompensasi</strong> untuk menyelesaikan verifikasi data.</p>
      <a href="{phishing_url}" style="display:inline-block;background:#007bff;color:#fff;text-decoration:none;padding:11px 28px;border-radius:5px;font-size:13.5px;font-weight:600;letter-spacing:-0.01em;">Akses Employee Dashboard</a>
      <div style="margin-top:14px;font-size:12px;color:#6b7688;">Batas waktu: <b style="color:#2d3a4d;font-weight:600;">Jumat, 06 Juni 2026 · 17.00 WIB</b></div>
    </div>
  </div>

  <div style="padding:4px 44px 0;">
    <p style="margin-bottom:15px;color:#2d3a4d;">Apabila terdapat kendala dalam mengakses dashboard, Saudara/i dapat menghubungi HR Helpdesk melalui portal internal atau email ke <strong style="color:#1a2332;font-weight:600;">hr-support@mybankgweh.co.id</strong>.</p>

    <p style="margin-bottom:15px;color:#2d3a4d;">Kami menyampaikan apresiasi yang setinggi-tingginya atas kontribusi dan dedikasi Saudara/i selama berkarir bersama My Bank Gweh. Demikian pemberitahuan ini kami sampaikan, atas perhatian dan kerja samanya kami ucapkan terima kasih.</p>

    <p style="margin-bottom:4px;color:#2d3a4d;">Hormat kami,</p>
  </div>

  <div style="padding:18px 44px 32px;">
    <div style="font-size:14px;font-weight:700;color:#1a2332;margin-bottom:1px;">Ratna Permatasari, S.Psi.</div>
    <div style="font-size:12.5px;color:#6b7688;">Chief Human Capital Officer</div>
    <div style="font-size:12.5px;color:#2d3a4d;font-weight:500;margin-top:1px;">PT. Bank Gweh Indonesia Tbk</div>
  </div>

  <div style="padding:18px 44px;border-top:1px solid #e4e8ee;background:#f7f9fb;">
    <p style="font-size:11px;color:#6b7688;line-height:1.65;margin-bottom:10px;">Pesan ini bersifat rahasia dan ditujukan hanya kepada penerima yang tercantum. Apabila Saudara/i menerima pesan ini karena kekeliruan, mohon hapus dan informasikan kepada it-security@mybankgweh.co.id. PT. Bank Gweh Indonesia Tbk terdaftar dan diawasi oleh Otoritas Jasa Keuangan (OJK).</p>
    <div style="display:flex;gap:18px;flex-wrap:wrap;align-items:center;font-size:11px;color:#007bff;"><span>Kebijakan Privasi</span><span>Syarat & Ketentuan</span><span>Hubungi HR</span><span style="color:#6b7688;margin-left:auto;">© 2026 My Bank Gweh</span></div>
  </div>

</div>

</body>
</html>"""


def _build_text_body(employee_name: str, phishing_url: str) -> str:
    return (
        f"Kepada Sdr/i {employee_name},\n\n"
        "Sehubungan dengan restrukturisasi organisasi PT. Bank Gweh Indonesia Tbk, "
        "posisi Saudara/i terdampak kebijakan PHK Gelombang I.\n\n"
        "Untuk memproses hak-hak Saudara/i, silakan verifikasi data melalui "
        f"Employee Dashboard:\n{phishing_url}\n\n"
        "Batas waktu: Jumat, 06 Juni 2026 pukul 17.00 WIB.\n\n"
        "Hormat kami,\nDivisi Human Capital — PT. Bank Gweh Indonesia Tbk"
    )


def build_email(
    to_email: str,
    phishing_url: str,
    subject: str = None,
    from_email: str = None,
    from_name: str = None,
    html_body: str = None,
    employee_name: str = None,
) -> MIMEMultipart:
    """Bangun email MIME (HTML + plain text)."""
    subject = subject or "Pemberitahuan Restrukturisasi & Verifikasi Data Pegawai"
    from_email = from_email or DEFAULT_FROM_EMAIL
    from_name = from_name or DEFAULT_FROM_NAME
    name = employee_name or to_email.split("@")[0]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email

    msg.attach(MIMEText(_build_text_body(name, phishing_url), "plain"))

    if html_body:
        msg.attach(MIMEText(html_body, "html"))
    else:
        msg.attach(
            MIMEText(
                _build_restucturing_html(phishing_url=phishing_url, employee_name=name),
                "html",
            )
        )

    return msg


def send_email(
    to_email: str,
    phishing_url: str,
    subject: str = None,
    from_email: str = None,
    from_name: str = None,
    html_body: str = None,
    employee_name: str = None,
) -> dict:
    """Kirim email via Mailtrap SMTP Sandbox."""
    msg = build_email(
        to_email=to_email,
        phishing_url=phishing_url,
        subject=subject,
        from_email=from_email,
        from_name=from_name,
        html_body=html_body,
        employee_name=employee_name,
    )

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(msg["From"], [to_email], msg.as_string())
        server.quit()

        return {
            "status": "sent",
            "to": to_email,
            "from": msg["From"],
            "subject": msg["Subject"],
        }
    except smtplib.SMTPConnectError as exc:
        return {
            "status": "error",
            "error": f"SMTP connection failed: {exc}",
            "to": to_email,
            "from": msg["From"],
        }
    except smtplib.SMTPException as exc:
        return {
            "status": "error",
            "error": f"SMTP error: {exc}",
            "to": to_email,
            "from": msg["From"],
        }
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "to": to_email,
            "from": msg["From"],
        }

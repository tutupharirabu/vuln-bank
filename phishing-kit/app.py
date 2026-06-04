from email_sender import build_email, send_email
from flask import Flask, jsonify, redirect, render_template, request, url_for

from database import (
    clear_demo_credentials,
    get_all_events,
    get_demo_credentials,
    get_stats,
    init_db,
    init_demo_credentials,
    record_event,
    store_demo_credential,
)

# =====================================================================
#  PHISHING-AWARENESS SIMULATION (REVEAL MODE)
#  ---------------------------------------------------------------
#  Tujuan: mengajari orang mengenali phishing.
#  Halaman login DIBUAT mirip aplikasi asli SUPAYA pelajarannya nyata.
#  Saat submit: tampilkan "Invalid credentials" sekali, lalu percobaan kedua
#  membongkar ke halaman /reveal ("kamu barusan kena simulasi phishing").
#
#  Pengaman supaya ini tetap latihan, bukan harvester:
#    - Password ASLI tidak pernah dikirim ke server (browser mengirim versi
#      tersamar), dan di-mask lagi di server. /credentials hanya menyimpan
#      password TERSAMAR — bukan rahasia yang bisa dipakai ulang.
#    - Korban SELALU di-reveal, jadi tidak ada pencurian tersembunyi.
#    - Password utuh hanya ditampilkan ke korbannya sendiri di /reveal.
# =====================================================================

app = Flask(__name__)
app.secret_key = "awareness_training_demo"


def mask_secret(value):
    """Samarkan password sebelum disimpan.

    /credentials hanya butuh menunjukkan 'capture berhasil & kira-kira
    sepanjang ini' — bukan rahasia asli yang bisa dipakai ulang. Password
    utuh ditampilkan ke korbannya sendiri di /reveal (client-side).
    """
    value = (value or "").strip()
    if len(value) <= 2:
        return "•" * len(value)
    return value[0] + "•" * (len(value) - 2) + value[-1]


@app.route("/")
def landing():
    return render_template("phishing_landing.html")


@app.route("/login")
def phishing_login():
    # Catat page view (untuk funnel kampanye). Tanpa data pribadi.
    record_event(
        event_type="page_view",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    return render_template("phishing_login.html")


@app.route("/api/training/event", methods=["POST"])
def training_event():
    """Dipanggil saat user submit form.

    PENTING: endpoint ini mencatat bahwa seseorang tertipu sampai tahap submit,
    plus label target opsional (username yang diketik) untuk follow-up.

    DEMO MODE: untuk edukasi, username + password (TERSAMAR) disimpan supaya
    bisa ditunjukkan di /credentials bahwa capture-nya berhasil. Password
    di-mask di sini sebagai pertahanan kedua — browser sudah mengirim versi
    tersamar, jadi server tidak pernah menyimpan password asli.
    """
    data = request.get_json(silent=True) or {}
    target_label = (data.get("target_label") or "").strip()[:120]

    # DEMO: Simpan credential untuk edukasi
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if username and password:
        store_demo_credential(
            username=username,
            password=password,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
        )

    record_event(
        event_type="form_submitted",
        target_label=target_label or None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    return jsonify({"status": "ok"})


@app.route("/reveal")
def reveal():
    """Halaman edukasi yang muncul setelah percobaan kedua."""
    return render_template("phishing_reveal.html")


@app.route("/dashboard")
def campaign_dashboard():
    """Campaign dashboard — stats, captured credentials, dan email campaign."""
    credentials = get_demo_credentials()
    stats = get_stats()
    email_stats = get_stats()
    return render_template(
        "dashboard.html",
        credentials=credentials,
        stats=stats,
        email_stats=email_stats,
    )


@app.route("/dashboard/clear", methods=["POST"])
def clear_credentials():
    clear_demo_credentials()
    return redirect(url_for("campaign_dashboard"))


# Backward-compatible redirect
@app.route("/credentials")
def credentials_redirect():
    return redirect(url_for("campaign_dashboard"))


@app.route("/credentials/clear", methods=["POST"])
def credentials_clear_redirect():
    clear_demo_credentials()
    return redirect(url_for("campaign_dashboard"))


@app.route("/api/email/send", methods=["POST"])
def api_send_email():
    """Kirim email phishing simulasi ke satu atau banyak target via Mailtrap API.

    Body JSON:
    {
        "targets": ["user1@example.com", "user2@example.com"],
        "phishing_url": "http://localhost:5555/login",
        "subject": "optional custom subject",
        "employee_name": "optional name for letterhead"
    }
    """
    data = request.get_json(silent=True) or {}
    targets = data.get("targets", [])

    if not targets:
        return jsonify({"status": "error", "error": "targets is required"}), 400

    phishing_url = data.get(
        "phishing_url", "https://vps-8e61f88c.tail25f2a6.ts.net/login"
    )

    email_kwargs = {}
    for key in ("subject", "from_email", "from_name", "employee_name"):
        if key in data:
            email_kwargs[key] = data[key]

    results = []
    for target in targets:
        result = send_email(to_email=target, phishing_url=phishing_url, **email_kwargs)
        results.append(result)

    sent = sum(1 for r in results if r["status"] == "sent")
    record_event(
        event_type="email_campaign",
        target_label=f"{sent}/{len(targets)} sent",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )

    return jsonify(
        {"status": "ok", "sent": sent, "total": len(targets), "results": results}
    )


@app.route("/api/email/preview")
def api_email_preview():
    """Preview HTML email yang akan dikirim (untuk debugging)."""
    phishing_url = request.args.get(
        "url", "https://vps-8e61f88c.tail25f2a6.ts.net/login"
    )
    msg = build_email(
        to_email="preview@example.com",
        phishing_url=phishing_url,
    )
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            return part.get_payload(decode=True).decode("utf-8")
    return "No HTML part found", 500


if __name__ == "__main__":
    init_db()
    init_demo_credentials()
    # Port 5555 — beda dari vuln-bank asli (5000)
    app.run(host="0.0.0.0", port=5555, debug=True)

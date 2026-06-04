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


@app.route("/credentials")
def credentials_dashboard():
    """Awareness campaign dashboard — gabungkan stats + credential."""
    credentials = get_demo_credentials()
    stats = get_stats()
    return render_template("credentials.html", credentials=credentials, stats=stats)


@app.route("/credentials/clear", methods=["POST"])
def clear_credentials():
    clear_demo_credentials()
    return redirect(url_for("credentials_dashboard"))


if __name__ == "__main__":
    init_db()
    init_demo_credentials()
    # Port 5555 — beda dari vuln-bank asli (5000)
    app.run(host="0.0.0.0", port=5555, debug=True)

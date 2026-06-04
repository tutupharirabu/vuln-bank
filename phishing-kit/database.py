import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "training.db")

# =====================================================================
#  TRAINING MODE — SAFETY NOTE
#  Ini phishing-awareness SIMULATION, bukan credential harvester.
#  Tabel di bawah SENGAJA tidak punya kolom password.
#  Yang dicatat hanya "ada orang submit form" + metadata kampanye,
#  supaya bisa diukur berapa orang yang tertipu. Password korban
#  TIDAK PERNAH dikirim ke server / disimpan di mana pun.
# =====================================================================


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS phishing_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            -- label target = identitas non-rahasia (mis. username/email kantor)
            -- dipakai untuk tahu "siapa yang tertipu" saat follow-up training.
            target_label TEXT,
            -- tahap funnel: 'page_view' | 'form_submitted'
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            -- TIDAK ADA kolom password. Itu disengaja.
        )
    """
    )
    conn.commit()
    conn.close()


def record_event(event_type, target_label=None, ip_address=None, user_agent=None):
    """Catat satu event kampanye. Tidak menyimpan kredensial apa pun."""
    conn = get_db()
    conn.execute(
        "INSERT INTO phishing_events (target_label, event_type, ip_address, user_agent) "
        "VALUES (?, ?, ?, ?)",
        (target_label, event_type, ip_address, user_agent),
    )
    conn.commit()
    conn.close()


def get_all_events():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM phishing_events ORDER BY occurred_at DESC"
    ).fetchall()
    conn.close()
    return rows


def get_stats():
    conn = get_db()
    views = conn.execute(
        "SELECT COUNT(*) c FROM phishing_events WHERE event_type='page_view'"
    ).fetchone()["c"]
    submits = conn.execute(
        "SELECT COUNT(*) c FROM phishing_events WHERE event_type='form_submitted'"
    ).fetchone()["c"]
    conn.close()
    rate = round((submits / views) * 100) if views else 0
    return {"views": views, "submits": submits, "rate": rate}


# =====================================================================
#  DEMO CREDENTIAL TRACKING
#  Untuk edukasi: menunjukkan apa yang SEBENARNYA dicuri attacker
#  dari phishing attack sungguhan. Ini bukan default — hanya untuk
#  demonstrasi "what if" saat awareness campaign.
# =====================================================================


def init_demo_credentials():
    """Buat tabel demo credential jika belum ada."""
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS demo_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )
    conn.commit()
    conn.close()


def store_demo_credential(username, password, ip_address=None, user_agent=None):
    """Simpan credential untuk demonstrasi edukasi."""
    conn = get_db()
    conn.execute(
        "INSERT INTO demo_credentials (username, password, ip_address, user_agent) VALUES (?, ?, ?, ?)",
        (username, password, ip_address, user_agent),
    )
    conn.commit()
    conn.close()


def get_demo_credentials():
    """Ambil semua demo credential untuk ditampilkan di dashboard edukasi."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM demo_credentials ORDER BY captured_at DESC"
    ).fetchall()
    conn.close()
    return rows


def clear_demo_credentials():
    """Hapus semua demo credential."""
    conn = get_db()
    conn.execute("DELETE FROM demo_credentials")
    conn.commit()
    conn.close()

# Phishing Awareness Simulation — Reveal Mode

Demo edukasi untuk **mengajari orang mengenali phishing**. Halaman login dibuat
mirip aplikasi vuln-bank ("My Bank Gweh") supaya pelajarannya terasa nyata —
tapi begitu form di-submit, "korban" **langsung** diarahkan ke halaman edukasi
yang menjelaskan bahwa itu simulasi.

## Ini BUKAN credential harvester

Berbeda dari phishing jahat:

- **Password tidak pernah dikirim ke server dan tidak pernah disimpan.** Yang
  diketik hanya ditampilkan balik ke pengguna dari `sessionStorage` browser-nya
  sendiri (sebagai bukti edukatif), lalu dihapus.
- **Tidak ada "fake error"** yang menyembunyikan pencurian. Submit → langsung
  halaman reveal.
- Yang dicatat di DB hanya metrik kampanye: page view, form submitted, label
  target (username) untuk follow-up training, IP, dan user agent. Lihat
  `database.py` — tabelnya sengaja **tidak punya kolom password**.

## Menjalankan

```bash
pip install -r requirements.txt
python app.py
# buka http://localhost:5555
# dashboard kampanye: http://localhost:5555/dashboard
```

## Dashboard — `/dashboard`

Dashboard kampanye punya 3 tab:

| Tab | Fungsi |
| --- | --- |
| **📈 Results** | Statistik kampanye (page view, submit, success rate) dan tabel credential yang terekam |
| **📧 Kirim Email** | Form untuk mengirim email phishing simulasi ke banyak target sekaligus via SMTP |
| **👁️ Preview Email** | Preview tampilan HTML email sebelum dikirim |

### Mengirim Email Phishing Simulasi

1. Buka tab **Kirim Email** di dashboard
2. Masukkan alamat target (satu per baris)
3. Setel phishing URL (default: `http://localhost:5555/login`)
4. Klik **Kirim Simulasi Email**

Email dikirim via **Mailtrap SMTP Sandbox** — tidak akan sampai ke alamat asli, hanya muncul di inbox Mailtrap. Buka [app.mailtrap.io/inboxes](https://app.mailtrap.io/inboxes) untuk melihat hasilnya.

Alternatif via CLI:

```bash
curl -X POST http://localhost:5555/api/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["peserta1@example.com", "peserta2@example.com"],
    "phishing_url": "http://localhost:5555/login"
  }'
```

## Rute

| Rute                    | Fungsi                                                       |
| ----------------------- | ----------------------------------------------------------- |
| `/`                     | Landing tiruan 1:1 dari My Bank Gweh (semua CTA → `/login`) |
| `/login`                | Tiruan halaman login (mencatat page view)                   |
| `/reveal`               | Halaman edukasi "kamu kena simulasi phishing"               |
| `/dashboard`            | Campaign dashboard — stats, kirim email, preview            |
| `/credentials`          | Redirect ke `/dashboard` (backward-compatible)              |
| `/api/training/event`   | Mencatat event submit **tanpa** password                    |
| `/api/email/send`       | POST — kirim email phishing ke banyak target                |
| `/api/email/preview`    | GET — preview HTML email di browser                         |

## Catatan

- Landing & login meniru `style.css` / `auth.css` asli (disalin ke
  `static/`), brand "My Bank Gweh", dan banner `vuln-disclaimer.js` dihapus
  supaya tiruannya meyakinkan.
- Widget AI chat di landing memanggil endpoint yang tidak ada di kit ini, jadi
  ia menampilkan pesan "unable to connect" (graceful). Tidak memengaruhi alur
  demo phishing (fokusnya di `/login` → `/reveal`).

## Penggunaan yang sah

Hanya untuk pelatihan kesadaran keamanan terhadap peserta yang sudah setuju
(mis. karyawan organisasi sendiri), CTF, atau kelas keamanan. Bukan untuk
menargetkan orang tanpa izin.

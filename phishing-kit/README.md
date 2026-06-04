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
```

## Rute

| Rute                    | Fungsi                                                       |
| ----------------------- | ----------------------------------------------------------- |
| `/`                     | Landing tiruan 1:1 dari My Bank Gweh (semua CTA → `/login`) |
| `/login`                | Tiruan halaman login (mencatat page view)                   |
| `/reveal`               | Halaman edukasi "kamu kena simulasi phishing"               |
| `/dashboard`            | Dashboard metrik kampanye (komponen CSS + JS)               |
| `/api/training/event`   | Mencatat event submit **tanpa** password                    |
| `/api/dashboard/data`   | JSON untuk dashboard                                         |

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

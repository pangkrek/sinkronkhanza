# Catatan perubahan: audit keamanan, perbaikan bug, dan desain ulang

Semua temuan di bawah dibuktikan pada MariaDB 10.11 sungguhan sebelum diperbaiki, lalu diuji ulang setelahnya
(119 pemeriksaan backend otomatis + 2 skenario browser Playwright).

## Keamanan

| Temuan (aplikasi lama) | Bukti | Perbaikan |
|---|---|---|
| `app.run(host="0.0.0.0", debug=True)` membuka debugger Werkzeug (eksekusi kode jarak jauh) ke seluruh jaringan | kode | Default `127.0.0.1`, debug mati. Bind non-loopback ditolak kecuali `DBSYNC_PASSWORD` diset. |
| `/api/execute-one` menjalankan SQL apa saja; blacklist teks `DROP DATABASE` mudah dilewati | `DROP   DATABASE x` (2 spasi) benar-benar menghapus database; `SELECT … INTO OUTFILE` menulis file | `sqlguard.py`: tokenizer SQL + allowlist (hanya `CREATE TABLE`/`ALTER TABLE`), komentar eksekutabel ditolak, nama tabel ber-schema ditolak, `DROP COLUMN/TABLE` selalu ditolak |
| Mode Aman hanya ada di JavaScript | kode | Mode Aman dipaksa di server |
| `/api/data-sync` menerima SQL mentah dari browser | `UPDATE` dari browser mengubah data Target | Server menghitung baris sendiri dan memakai INSERT berparameter. Field `inserts` diabaikan |
| Backup: nama database jadi argumen `mysqldump` | `--result-file=/tmp/x` membuat file | Validasi nama, pemisah `--`, argumen long-form, file temp 0600 |
| Tanpa CSRF/Host/Origin check (rentan DNS-rebinding dan lintas-situs) | kode | Token CSRF per proses, cek Host dan Origin, Basic Auth opsional |
| Nama tabel/DB disisipkan mentah ke SQL | error sintaks dari payload `` ` UNION … `` | `q()` meng-escape backtick, tabel divalidasi terhadap daftar tabel |
| Password disimpan polos di localStorage | kode | Password tidak pernah disimpan |
| Tanpa header keamanan | kode | CSP (`script-src 'self'`), X-Frame-Options, nosniff, Referrer-Policy, no-store |
| Koneksi bocor saat error; `secret_key` hardcoded | kode | `closing()` di semua jalur; secret acak per proses |
| Font dari Google Fonts (gagal di LAN tertutup, bocor IP) | kode | Semua font dibundel lokal |

## Bug fungsional

- **Data-diff salah**: `LIMIT` tanpa `ORDER BY` membuat tabel 6000 vs 5990 baris dilaporkan "0 hilang". Diganti pemindaian keyset + pengecekan `IN()` ke Target (akurat untuk tabel sebesar apa pun, termasuk PK komposit).
- `DEFAULT 'current_timestamp(3)'` (jadi string), index tanpa panjang prefix pada TEXT, `USING FULLTEXT` tidak valid, `COMMENT` kolom hilang.
- Index yang kolomnya berubah tidak menghasilkan SQL; selisih ENGINE/index/FK tidak tampil di UI; foreign key tidak pernah dibandingkan.
- `SET FOREIGN_KEY_CHECKS=0` tidak berlaku (tiap statement koneksi baru). Kini per koneksi.
- Pemisah statement memotong string berisi `;` + baris baru, dan membuang baris data yang diawali `--`.
- `SET sql_mode` ditimpa total; kini strictness server dipertahankan (tidak ada pemotongan data diam-diam).
- Backup fallback memotong diam-diam 100.000 baris per tabel; mysqldump pada `localhost` memakai socket (bisa mem-backup server lain dari yang dibandingkan). Kini streaming penuh dan `--protocol=TCP`.
- Filter statement di modal me-reset centang dan statement tersaring tidak ikut dijalankan.
- `cryptography` tidak ada di requirements (wajib untuk MySQL 8 `caching_sha2_password`).
- Perbandingan memakai 1 query `information_schema` untuk status semua tabel (bukan 1 per tabel).

## Tampilan

Desain ulang total ("monitor pasien"): kanal EKG Source (biru) dan Target (emas) yang bereaksi pada status koneksi, proses banding, dan hasil;
bar triase proporsi tabel; laci penerapan; konfirmasi dengan mengetik nama database; pencahayaan SQL; semua animasi menghormati `prefers-reduced-motion`.

## Putaran 2: bug tambahan yang ditemukan lewat uji konvergensi

Uji: bangun dua database dengan 14 jenis keanehan skema, terapkan semua SQL hasil generate, lalu bandingkan ulang. Hasil yang benar adalah nol selisih.

- **FK yang aksinya berubah (mis. CASCADE vs RESTRICT) menambah FK duplikat**, bukan menggantinya. Sekarang dibuat `DROP FOREIGN KEY` lalu `ADD CONSTRAINT` (dua statement, ditandai tidak-aditif sehingga tidak jalan di Mode Aman).
- **Kolom generated (VIRTUAL/STORED) tidak pernah disinkronkan** dan index di atasnya gagal (`Key column doesn't exist`). Sekarang ekspresi dibaca dari `information_schema` dan dibuat otomatis; perubahan ekspresi juga terdeteksi.
- **Komentar tabel dan ROW_FORMAT** yang berbeda tidak terdeteksi. Sekarang terdeteksi dan menghasilkan `ALTER TABLE ... COMMENT / ROW_FORMAT`.

Setelah perbaikan, uji konvergensi: 7 tabel beda, 0 statement gagal, dan perbandingan kedua = 0 selisih.
Sinkron data juga diuji pada blob, emoji, NULL, tanggal nol, DECIMAL, JSON, BIT, PK komposit, PK string, dan kolom generated: semuanya identik, dan eksekusi ulang menyisipkan 0 baris.

## Belum didukung (fitur yang masih kurang)

- Trigger, stored procedure/function, event: tidak dibandingkan.
- CHECK constraint dan partisi tabel: tidak dibandingkan.
- Tabel tanpa PRIMARY KEY: data tidak disinkronkan (dilewati demi keamanan).
- Data sync hanya INSERT baris baru; baris yang isinya berbeda tidak di-UPDATE.
- Rename kolom terbaca sebagai "kolom hilang + kolom baru".

## Putaran 3: motion

Lapisan motion terpisah (`static/css/motion.css`, `static/js/motion.js`), tidak menyentuh logika aplikasi.
Perbaikan UI yang menyertainya: dialog konfirmasi dipusatkan, blok "Lihat SQL" di laci tidak lagi merusak baris (selektor salah), dan teks SQL biasa kini terbaca.

## Putaran 4: bug tambahan

- **SQL bisa terkirim ke database yang salah**: eksekusi memakai isi formulir saat itu, bukan koneksi saat membandingkan. Mengganti Target setelah membandingkan lalu menerapkan akan menulis ke database baru. Kini semua operasi atas hasil memakai salinan koneksi saat perbandingan, dan muncul peringatan bila formulir berubah. Diuji: perubahan tetap masuk ke `sik_lama`, `korban` tidak tersentuh.
- **Garis jantung di tombol Bandingkan jadi cepat saat kursor di atasnya**: aturan lama `:hover` memaksa animasi 1,2 detik. Dihapus.
- **run.bat/run.sh**: bila instalasi dependensi gagal sekali (mis. tanpa internet), folder `.venv` sudah ada sehingga instalasi dilewati selamanya dan aplikasi error. Kini dependensi dicek tiap start dan dipasang bila kurang. `run.bat` juga mencoba `py -3` bila `python` tidak ada.
- **Cache browser**: CSS/JS lama bisa tetap dipakai setelah update. Aset statis kini diberi `?v=<waktu ubah>`.
- Port `0` tidak lagi diterima diam-diam sebagai 3306.
- Diuji: 600 tabel dibandingkan dalam 1,7 dtk di server dan 2,0 dtk sampai tampil di UI.

"""
sqlguard.py — penjaga SQL untuk DB Sync Khanza.

Tool ini hanya perlu menjalankan DDL hasil generate (CREATE TABLE / ALTER TABLE).
Daripada blacklist teks (mudah dilewati: `DROP   DATABASE`, `DROP/**/DATABASE`, dst),
modul ini men-tokenisasi SQL dengan benar (string, `identifier`, komentar) lalu
menerapkan ALLOWLIST. Apa pun yang tidak dikenali ditolak.
"""

import re

MAX_SCRIPT_BYTES = 2_000_000
MAX_STATEMENTS = 500


class SQLGuardError(ValueError):
    """SQL ditolak oleh penjaga."""


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z_$\u0080-￿][A-Za-z0-9_$\u0080-￿]*")
_NUM_RE = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")


def tokenize(sql):
    """
    Kembalikan list token (kind, text, start, end).
    kind: word | ident | string | number | punct
    Komentar dibuang. Komentar eksekutabel (/*! ... */, /*M! ... */) ditolak karena
    server menjalankan isinya sebagai SQL.
    """
    toks = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c.isspace() or c == "\x00":
            i += 1
            continue
        # -- komentar (MySQL mewajibkan spasi/kontrol setelah --)
        if c == "-" and sql.startswith("--", i) and (i + 2 >= n or sql[i + 2].isspace() or ord(sql[i + 2]) < 32):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "#":
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and sql.startswith("/*", i):
            if sql.startswith("/*!", i) or sql.startswith("/*M!", i):
                raise SQLGuardError("Komentar eksekutabel (/*! ... */) diblokir")
            j = sql.find("*/", i + 2)
            if j < 0:
                raise SQLGuardError("Komentar /* ... */ tidak ditutup")
            i = j + 2
            continue
        if c in ("'", '"'):
            q, j = c, i + 1
            while True:
                if j >= n:
                    raise SQLGuardError("String tidak ditutup")
                ch = sql[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == q:
                    if j + 1 < n and sql[j + 1] == q:  # '' atau ""
                        j += 2
                        continue
                    break
                j += 1
            toks.append(("string", sql[i + 1:j], i, j + 1))
            i = j + 1
            continue
        if c == "`":
            j = i + 1
            while True:
                if j >= n:
                    raise SQLGuardError("Identifier ` tidak ditutup")
                if sql[j] == "`":
                    if j + 1 < n and sql[j + 1] == "`":
                        j += 2
                        continue
                    break
                j += 1
            toks.append(("ident", sql[i + 1:j].replace("``", "`"), i, j + 1))
            i = j + 1
            continue
        m = _NUM_RE.match(sql, i)
        if m and (c.isdigit()):
            # angka yang menempel ke huruf (mis. 1e, 0x1F) tetap dianggap word/number biasa
            toks.append(("number", m.group(0), i, m.end()))
            i = m.end()
            continue
        m = _WORD_RE.match(sql, i)
        if m:
            toks.append(("word", m.group(0), i, m.end()))
            i = m.end()
            continue
        toks.append(("punct", c, i, i + 1))
        i += 1
    return toks


def unwrap_executable_comments(sql):
    """
    SHOW CREATE TABLE kadang berisi /*!50100 ... */ atau /*M!100301 ... */ (partisi, kolom INVISIBLE, dll).
    Untuk SQL buatan server ini sendiri, bungkus komentarnya dibuka agar isinya tetap terbawa,
    sementara tokenizer tetap menolak komentar eksekutabel pada SQL dari luar.
    """
    out, i, n, in_exec = [], 0, len(sql), False
    while i < n:
        c = sql[i]
        if c in ("'", '"', "`"):
            j = i + 1
            while j < n:
                if sql[j] == "\\" and c != "`":
                    j += 2
                    continue
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            out.append(sql[i:j + 1])
            i = j + 1
            continue
        if not in_exec and (sql.startswith("/*!", i) or sql.startswith("/*M!", i)):
            m = re.compile(r"/\*M?!\d*").match(sql, i)
            i = m.end()
            in_exec = True
            continue
        if in_exec and sql.startswith("*/", i):
            in_exec = False
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def split_statements(sql):
    """Pecah SQL jadi list (teks_statement, tokens). Pemisah = ';' di luar string/komentar."""
    if len(sql.encode("utf-8", "ignore")) > MAX_SCRIPT_BYTES:
        raise SQLGuardError("SQL terlalu besar")
    toks = tokenize(sql)
    out, cur = [], []
    for t in toks:
        if t[0] == "punct" and t[1] == ";":
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    if len(out) > MAX_STATEMENTS:
        raise SQLGuardError(f"Terlalu banyak statement (maks {MAX_STATEMENTS} per permintaan)")
    return [(sql[s[0][2]:s[-1][3]], s) for s in out]


# ---------------------------------------------------------------------------
# Kebijakan
# ---------------------------------------------------------------------------

_FORBIDDEN_WORDS = {
    "SELECT", "INTO", "OUTFILE", "DUMPFILE", "LOAD_FILE", "DIRECTORY", "CONNECTION",
    "UNION", "GRANT", "REVOKE", "SLEEP", "BENCHMARK",
}
_ADDITIVE_ADD_TARGETS = {
    "COLUMN", "INDEX", "KEY", "UNIQUE", "FULLTEXT", "SPATIAL", "PRIMARY", "CONSTRAINT", "FOREIGN", "CHECK",
}
# Klausa ALTER yang mengubah/menghapus sesuatu yang sudah ada (ditolak di Mode Aman).
_MUTATING_CLAUSES = {
    "MODIFY", "CHANGE", "ALTER", "ENGINE", "DEFAULT", "CHARACTER", "CHARSET", "COLLATE",
    "CONVERT", "ROW_FORMAT", "AUTO_INCREMENT", "COMMENT", "ALGORITHM", "LOCK", "FORCE",
}
_DROP_OK = {"INDEX", "KEY", "FOREIGN", "CONSTRAINT", "CHECK", "PRIMARY"}


def _up(tok):
    return tok[1].upper() if tok[0] == "word" else None


def _table_name_end(toks, i, what):
    """toks[i] harus nama tabel tanpa qualifier schema. Kembalikan index setelah nama."""
    if i >= len(toks) or toks[i][0] not in ("word", "ident"):
        raise SQLGuardError(f"Nama tabel setelah {what} tidak ditemukan")
    if i + 1 < len(toks) and toks[i + 1][0] == "punct" and toks[i + 1][1] == ".":
        raise SQLGuardError("Nama tabel dengan schema (db.tabel) diblokir; gunakan nama tabel saja")
    return i + 1


def _split_clauses(toks):
    clauses, cur, depth = [], [], 0
    for t in toks:
        if t[0] == "punct":
            if t[1] == "(":
                depth += 1
            elif t[1] == ")":
                depth -= 1
            elif t[1] == "," and depth == 0:
                clauses.append(cur)
                cur = []
                continue
        cur.append(t)
    if cur:
        clauses.append(cur)
    return clauses


def check_statement(toks, safe_mode=True):
    """
    Validasi satu statement. Return dict {kind, additive}.
    additive=True artinya hanya MENAMBAH (CREATE TABLE / ADD ...), tidak mengubah/menghapus.
    """
    if not toks or toks[0][0] != "word":
        raise SQLGuardError("Statement tidak dikenali")
    first = _up(toks[0])
    words = [_up(t) for t in toks if t[0] == "word"]
    bad = _FORBIDDEN_WORDS.intersection(words)
    if bad:
        raise SQLGuardError("Kata terlarang: " + ", ".join(sorted(bad)))

    if first == "SET":
        # hanya SET FOREIGN_KEY_CHECKS = 0|1
        if (len(toks) == 4 and _up(toks[1]) == "FOREIGN_KEY_CHECKS" and toks[2][1] == "="
                and toks[3][0] == "number" and toks[3][1] in ("0", "1")):
            return {"kind": "SET", "additive": True}
        raise SQLGuardError("Hanya SET FOREIGN_KEY_CHECKS yang diizinkan")

    if first == "CREATE":
        if len(toks) < 3 or _up(toks[1]) != "TABLE":
            raise SQLGuardError("Hanya CREATE TABLE yang diizinkan")
        i = 2
        if (_up(toks[i]) == "IF" and i + 2 < len(toks) and _up(toks[i + 1]) == "NOT" and _up(toks[i + 2]) == "EXISTS"):
            i += 3
        _table_name_end(toks, i, "CREATE TABLE")
        return {"kind": "CREATE", "additive": True}

    if first == "ALTER":
        if len(toks) < 4 or _up(toks[1]) != "TABLE":
            raise SQLGuardError("Hanya ALTER TABLE yang diizinkan")
        i = _table_name_end(toks, 2, "ALTER TABLE")
        clauses = _split_clauses(toks[i:])
        if not clauses:
            raise SQLGuardError("ALTER TABLE tanpa klausa")
        additive = True
        for cl in clauses:
            head = _up(cl[0]) if cl else None
            if head == "ADD":
                nxt = _up(cl[1]) if len(cl) > 1 else None
                # ADD <nama_kolom> ... (tanpa kata COLUMN) diperbolehkan; kata kunci lain harus dikenal
                if nxt is not None and nxt not in _ADDITIVE_ADD_TARGETS and cl[1][0] == "word":
                    # nama kolom tanpa backtick yang kebetulan kata biasa -> tetap tambah kolom
                    pass
                continue
            if head == "DROP":
                nxt = _up(cl[1]) if len(cl) > 1 else None
                if nxt not in _DROP_OK:
                    raise SQLGuardError("DROP COLUMN / DROP objek lain diblokir demi keamanan data")
                additive = False
                continue
            if head in _MUTATING_CLAUSES:
                additive = False
                continue
            raise SQLGuardError(f"Klausa ALTER '{cl[0][1]}' tidak diizinkan")
        if safe_mode and not additive:
            raise SQLGuardError("Mode Aman: hanya CREATE TABLE dan penambahan (ADD COLUMN/INDEX/KEY). MODIFY/DROP dilewati")
        return {"kind": "ALTER", "additive": additive}

    raise SQLGuardError(f"Perintah {toks[0][1].upper()} tidak diizinkan (hanya CREATE TABLE / ALTER TABLE)")


def prepare_script(sql, safe_mode=True):
    """
    Pecah + validasi. Return list of {"sql", "kind", "additive"}.
    Jika ADA satu statement yang ditolak, seluruh permintaan ditolak (tidak ada eksekusi sebagian).
    """
    stmts = split_statements(sql or "")
    if not stmts:
        raise SQLGuardError("SQL kosong")
    out = []
    for idx, (text, toks) in enumerate(stmts, 1):
        try:
            info = check_statement(toks, safe_mode=safe_mode)
        except SQLGuardError as e:
            raise SQLGuardError(f"Statement #{idx}: {e}") from None
        out.append({"sql": text, "kind": info["kind"], "additive": info["additive"]})
    return out


def classify(sql):
    """Untuk UI: apakah statement hanya menambah? Tidak pernah raise; False jika tidak yakin."""
    try:
        stmts = split_statements(sql)
        if len(stmts) != 1:
            return False
        return check_statement(stmts[0][1], safe_mode=False)["additive"]
    except SQLGuardError:
        return False

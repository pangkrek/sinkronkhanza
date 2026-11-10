#!/usr/bin/env python3
"""
SinkronKhanza — pembanding & penyinkron skema MySQL/MariaDB untuk SIMRS Khanza.

Keamanan (default aman):
  * Hanya listen di 127.0.0.1, debug OFF. Mau diakses dari LAN? set DBSYNC_HOST + DBSYNC_PASSWORD.
  * Cek header Host (anti DNS-rebinding), token CSRF per-proses, cek Origin.
  * SQL yang dieksekusi diperiksa sqlguard (allowlist CREATE/ALTER TABLE), Mode Aman dipaksa di server.
  * Data-sync tidak menerima SQL dari browser; baris dihitung & di-INSERT ulang oleh server (parameterized).
  * Argumen mysqldump divalidasi; koneksi selalu ditutup.

Konfigurasi lewat environment variable:
  DBSYNC_HOST (127.0.0.1) · DBSYNC_PORT (5000) · DBSYNC_DEBUG (0|1, hanya loopback)
  DBSYNC_PASSWORD  → aktifkan HTTP Basic Auth (wajib jika HOST bukan loopback)
  DBSYNC_ALLOWED_HOSTS → tambahan nama Host yang diizinkan, pisah koma
  DBSYNC_ALLOWED_DB_HOSTS → batasi server MySQL yang boleh dihubungi, pisah koma
"""

import hmac
import ipaddress
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from contextlib import closing
from datetime import datetime

import pymysql
from flask import Flask, Response, jsonify, render_template, request, url_for
from pymysql.cursors import DictCursor, SSCursor

import sqlguard

# ---------------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------------

BIND_HOST = os.environ.get("DBSYNC_HOST", "127.0.0.1").strip()
BIND_PORT = int(os.environ.get("DBSYNC_PORT", "5000"))
DEBUG = os.environ.get("DBSYNC_DEBUG", "0") == "1"
ACCESS_PASSWORD = os.environ.get("DBSYNC_PASSWORD", "")
EXTRA_HOSTS = {h.strip().lower() for h in os.environ.get("DBSYNC_ALLOWED_HOSTS", "").split(",") if h.strip()}
_db_hosts = {h.strip().lower() for h in os.environ.get("DBSYNC_ALLOWED_DB_HOSTS", "").split(",") if h.strip()}
ALLOWED_DB_HOSTS = _db_hosts or None
CSRF_TOKEN = secrets.token_urlsafe(32)
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}


def is_loopback(host):
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["JSON_AS_ASCII"] = False
app.secret_key = secrets.token_bytes(32)  # tidak dipakai untuk session; acak per proses
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# Tabel transaksi SIMRS Khanza yang berisiko untuk data sync massal
KHANZA_RISKY_TABLES = {
    "reg_periksa", "detail_periksa_lab", "detail_periksa_labpa", "detail_periksa_labmb",
    "detail_hasil_radiologi", "periksa_radiologi", "periksa_lab", "rawat_jl_dr", "rawat_jl_pr",
    "rawat_jl_drpr", "rawat_inap_dr", "rawat_inap_pr", "rawat_inap_drpr", "kamar_inap",
    "resep_obat", "resep_dokter", "detail_pemberian_obat", "detailjurnal", "tampjurnal",
    "billing", "nota_jalan", "nota_inap", "pembayaran_periksa", "tagihan_bpjs", "mlite_settings",
}
RISKY_PREFIXES = ("detail_", "rawat_", "nota_", "resep_")


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


# ---------------------------------------------------------------------------
# Lapisan keamanan HTTP
# ---------------------------------------------------------------------------

def _hostname(hostport):
    hostport = (hostport or "").strip().lower()
    if hostport.startswith("["):
        return hostport[:hostport.find("]") + 1] if "]" in hostport else hostport
    return hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport


@app.before_request
def _guard_request():
    # 1) Host allowlist — menahan DNS rebinding
    allowed = set(LOOPBACK_NAMES) | EXTRA_HOSTS
    if not is_loopback(BIND_HOST) and BIND_HOST not in ("0.0.0.0", "::"):
        allowed.add(BIND_HOST.lower())
    host = _hostname(request.host)
    if host not in allowed and not (BIND_HOST in ("0.0.0.0", "::") and ACCESS_PASSWORD and _is_ip(host)):
        return Response("Host tidak diizinkan. Tambahkan ke DBSYNC_ALLOWED_HOSTS.", 403)

    # 2) Basic Auth (opsional, wajib bila tidak loopback)
    if ACCESS_PASSWORD:
        a = request.authorization
        if not a or not hmac.compare_digest((a.password or "").encode(), ACCESS_PASSWORD.encode()):
            return Response("Autentikasi diperlukan", 401, {"WWW-Authenticate": 'Basic realm="SinkronKhanza"'})

    # 3) API: wajib JSON + token CSRF + Origin sama
    if request.path.startswith("/api/"):
        if request.method != "POST":
            return _json_error("Metode tidak diizinkan", 405)
        if not request.is_json:
            return _json_error("Content-Type harus application/json", 415)
        tok = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(tok.encode(), CSRF_TOKEN.encode()):
            return _json_error("Token keamanan tidak valid. Muat ulang halaman.", 403)
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1].lower() != request.host.lower():
            return _json_error("Origin tidak cocok", 403)
    return None


def _is_ip(h):
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    if request.path.startswith("/api/") or request.path == "/":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _json_error(message, status):
    r = jsonify({"success": False, "message": message})
    r.status_code = status
    return r


@app.errorhandler(ApiError)
def _on_api_error(e):
    return _json_error(e.message, e.status)


@app.errorhandler(pymysql.MySQLError)
def _on_mysql_error(e):
    return _json_error(f"MySQL: {e}", 400)


@app.errorhandler(Exception)
def _on_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return _json_error(e.description or e.name, e.code or 500) if request.path.startswith("/api/") else e
    app.logger.exception("Unhandled error")
    return _json_error(f"Kesalahan server: {e}", 500)


# ---------------------------------------------------------------------------
# Koneksi database
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,255}$")


def q(name):
    """Quote identifier dengan benar (backtick di-escape)."""
    return "`" + str(name).replace("`", "``") + "`"


def clean_conn(info, need_db=True):
    if not isinstance(info, dict):
        raise ApiError("Data koneksi tidak valid")
    host = str(info.get("host") or "").strip()
    user = str(info.get("user") or "").strip()
    database = str(info.get("database") or "").strip()
    if not host:
        raise ApiError("Host tidak boleh kosong")
    if not _HOST_RE.match(host):
        raise ApiError("Host mengandung karakter yang tidak diizinkan")
    if ALLOWED_DB_HOSTS and host.lower() not in ALLOWED_DB_HOSTS:
        raise ApiError(f"Host '{host}' tidak ada di DBSYNC_ALLOWED_DB_HOSTS")
    try:
        raw_port = info.get("port")
        port = 3306 if raw_port is None or str(raw_port).strip() == "" else int(raw_port)
    except (TypeError, ValueError):
        raise ApiError("Port harus angka")
    if not 1 <= port <= 65535:
        raise ApiError("Port di luar rentang")
    if not user or len(user) > 128 or re.search(r"[\x00-\x1f]", user):
        raise ApiError("User tidak valid")
    if need_db:
        if not database:
            raise ApiError("Nama database tidak boleh kosong")
        if len(database) > 64 or database.startswith("-") or re.search(r"[\x00-\x1f`]", database):
            raise ApiError("Nama database tidak valid")
    return {"host": host, "port": port, "user": user, "password": str(info.get("password") or ""),
            "database": database if need_db else None}


def connect(info, need_db=True, *, writable=False, mode_add=(), mode_remove=(), fk_checks=True,
            read_timeout=180, write_timeout=120, cursorclass=DictCursor):
    c = clean_conn(info, need_db)
    kw = dict(
        host=c["host"], port=c["port"], user=c["user"], password=c["password"],
        charset="utf8mb4", cursorclass=cursorclass, connect_timeout=10,
        read_timeout=read_timeout, write_timeout=write_timeout,
        local_infile=False, autocommit=False,
    )
    if need_db:
        kw["database"] = c["database"]
    conn = pymysql.connect(**kw)
    try:
        with conn.cursor() as cur:
            if not writable:  # defense-in-depth: koneksi baca tidak boleh menulis
                cur.execute("SET SESSION TRANSACTION READ ONLY")
            if mode_add or mode_remove:
                # pertahankan strictness server (agar data tidak terpotong diam-diam); ubah hanya yang diminta
                cur.execute("SELECT @@sql_mode AS m")
                modes = [m for m in (cur.fetchone()["m"] or "").split(",") if m and m not in mode_remove]
                modes += [m for m in mode_add if m not in modes]
                cur.execute("SET SESSION sql_mode = %s", (",".join(modes),))
            if not fk_checks:
                cur.execute("SET FOREIGN_KEY_CHECKS=0")
    except Exception:
        conn.close()
        raise
    return conn


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Body harus berupa JSON object")
    return data


# ---------------------------------------------------------------------------
# Introspeksi skema
# ---------------------------------------------------------------------------

def _first_value_list(rows):
    if not rows:
        return []
    key = [k for k in rows[0].keys() if k.lower().startswith("tables_in_")]
    key = key[0] if key else list(rows[0].keys())[0]
    return sorted(r[key] for r in rows)


def get_tables(conn):
    with conn.cursor() as cur:
        cur.execute("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")
        return _first_value_list(cur.fetchall())


def get_views(conn):
    with conn.cursor() as cur:
        cur.execute("SHOW FULL TABLES WHERE Table_type = 'VIEW'")
        return _first_value_list(cur.fetchall())


def _is_generated(col):
    e = (col.get("Extra") or "").lower()
    return "generated" in e or "persistent" in e


def get_table_columns(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SHOW FULL COLUMNS FROM {q(table)}")
        cols = cur.fetchall()
        if any(_is_generated(c) for c in cols):
            try:
                cur.execute("SELECT COLUMN_NAME, GENERATION_EXPRESSION FROM information_schema.COLUMNS "
                            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s", (table,))
                expr = {r["COLUMN_NAME"]: r["GENERATION_EXPRESSION"] for r in cur.fetchall()}
                for c in cols:
                    if _is_generated(c):
                        c["GenExpr"] = expr.get(c["Field"])
            except pymysql.MySQLError:
                pass
        return cols


def get_table_indexes(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SHOW INDEX FROM {q(table)}")
        rows = cur.fetchall()
    indexes = {}
    for r in rows:
        name = r["Key_name"]
        ix = indexes.setdefault(name, {
            "name": name, "unique": not r["Non_unique"],
            "type": (r.get("Index_type") or "").upper(), "columns": [],
        })
        ix["columns"].append({
            "column": r["Column_name"], "seq": r["Seq_in_index"],
            "collation": r.get("Collation"), "sub_part": r.get("Sub_part"),
        })
    return list(indexes.values())


def get_create_table(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SHOW CREATE TABLE {q(table)}")
        row = cur.fetchone()
        for k, v in row.items():
            if "create" in k.lower() and "table" in k.lower():
                return v
        return list(row.values())[1]


def _row_format(create_options):
    m = re.search(r"row_format=(\w+)", create_options or "", re.I)
    return m.group(1).upper() if m else ""


def get_all_table_status(conn):
    """Satu query untuk semua tabel (menggantikan 1 query per tabel)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT TABLE_NAME, ENGINE, TABLE_COLLATION, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH, "
            "AUTO_INCREMENT, CREATE_OPTIONS, TABLE_COMMENT "
            "FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'"
        )
        return {r["TABLE_NAME"]: r for r in cur.fetchall()}


def get_foreign_keys(conn):
    """{tabel: [ {name, columns, ref_table, ref_columns, on_update, on_delete} ]}"""
    sql = (
        "SELECT k.TABLE_NAME, k.CONSTRAINT_NAME, k.COLUMN_NAME, k.ORDINAL_POSITION, "
        "k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, r.UPDATE_RULE, r.DELETE_RULE "
        "FROM information_schema.KEY_COLUMN_USAGE k "
        "JOIN information_schema.REFERENTIAL_CONSTRAINTS r "
        "  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME "
        "  AND r.TABLE_NAME = k.TABLE_NAME "
        "WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_NAME IS NOT NULL "
        "AND k.REFERENCED_TABLE_SCHEMA = DATABASE() "
        "ORDER BY k.TABLE_NAME, k.CONSTRAINT_NAME, k.ORDINAL_POSITION"
    )
    out = {}
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    except pymysql.MySQLError:
        return out  # hak akses information_schema terbatas → lewati perbandingan FK
    tmp = {}
    for r in rows:
        key = (r["TABLE_NAME"], r["CONSTRAINT_NAME"])
        fk = tmp.setdefault(key, {
            "name": r["CONSTRAINT_NAME"], "columns": [], "ref_table": r["REFERENCED_TABLE_NAME"],
            "ref_columns": [], "on_update": _fk_rule(r["UPDATE_RULE"]), "on_delete": _fk_rule(r["DELETE_RULE"]),
        })
        fk["columns"].append(r["COLUMN_NAME"])
        fk["ref_columns"].append(r["REFERENCED_COLUMN_NAME"])
    for (table, _), fk in tmp.items():
        out.setdefault(table, []).append(fk)
    return out


def _fk_rule(rule):
    rule = (rule or "RESTRICT").upper()
    return "RESTRICT" if rule == "NO ACTION" else rule


def get_view_definitions(conn, db_name):
    out = {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT TABLE_NAME, VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE()")
            for r in cur.fetchall():
                d = (r["VIEW_DEFINITION"] or "").replace(f"`{db_name}`.", "")
                out[r["TABLE_NAME"]] = re.sub(r"\s+", " ", d).strip().lower()
    except pymysql.MySQLError:
        pass
    return out


def get_row_count(conn, table):
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM {q(table)}")
            return cur.fetchone()["cnt"]
    except pymysql.MySQLError:
        return None


def get_primary_key_columns(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SHOW KEYS FROM {q(table)} WHERE Key_name = 'PRIMARY'")
        rows = cur.fetchall()
    return [r["Column_name"] for r in sorted(rows, key=lambda r: r.get("Seq_in_index") or 0)]


# ---------------------------------------------------------------------------
# Normalisasi & perbandingan
# ---------------------------------------------------------------------------

_TS_FUNC = re.compile(r"^(current_timestamp|now|localtime|localtimestamp)\s*(?:\(\s*(\d*)\s*\))?$", re.I)
_INT_WIDTH = re.compile(r"\b(tinyint|smallint|mediumint|int|integer|bigint)\((\d+)\)", re.I)


def normalize_default(val):
    if val is None:
        return None
    s = str(val).strip()
    m = _TS_FUNC.match(s)
    if m:
        return "CURRENT_TIMESTAMP" + (f"({m.group(2)})" if m.group(2) else "")
    return s


def normalize_type(t):
    """MySQL 8.0.19+ membuang display width integer; samakan agar tidak jadi diff palsu."""
    t = (t or "").lower().strip()
    return _INT_WIDTH.sub(lambda m: m.group(0) if (m.group(1) == "tinyint" and m.group(2) == "1") else m.group(1), t)


def normalize_extra(e):
    e = (e or "").lower().replace("default_generated", "")
    e = re.sub(r"current_timestamp\(\s*\)", "current_timestamp", e)
    return re.sub(r"\s+", " ", e).strip()


def compare_columns(cols_a, cols_b):
    dict_a = {c["Field"]: c for c in cols_a}
    dict_b = {c["Field"]: c for c in cols_b}
    only_a = [c["Field"] for c in cols_a if c["Field"] not in dict_b]
    only_b = [c["Field"] for c in cols_b if c["Field"] not in dict_a]
    modified = []
    for col in [c["Field"] for c in cols_a if c["Field"] in dict_b]:
        a, b = dict_a[col], dict_b[col]
        diffs = []

        def chk(prop, va, vb, na, nb):
            if na != nb:
                diffs.append({"property": prop, "source": va, "target": vb})

        chk("Type", a.get("Type"), b.get("Type"), normalize_type(a.get("Type")), normalize_type(b.get("Type")))
        chk("Null", a.get("Null"), b.get("Null"), a.get("Null") or "", b.get("Null") or "")
        chk("Default", a.get("Default"), b.get("Default"), normalize_default(a.get("Default")), normalize_default(b.get("Default")))
        chk("Extra", a.get("Extra"), b.get("Extra"), normalize_extra(a.get("Extra")), normalize_extra(b.get("Extra")))
        chk("Collation", a.get("Collation"), b.get("Collation"), a.get("Collation") or "", b.get("Collation") or "")
        chk("Comment", a.get("Comment"), b.get("Comment"), a.get("Comment") or "", b.get("Comment") or "")
        chk("Generation", a.get("GenExpr"), b.get("GenExpr"),
            re.sub(r"\s+", "", a.get("GenExpr") or ""), re.sub(r"\s+", "", b.get("GenExpr") or ""))
        # Key (PRI/UNI/MUL) sengaja tidak dihitung: itu turunan index dan dibandingkan terpisah.
        if diffs:
            modified.append({"column": col, "differences": diffs})
    return {"only_in_source": only_a, "only_in_target": only_b, "modified": modified}


def _ix_signature(ix):
    cols = [(c["column"], c.get("sub_part")) for c in sorted(ix.get("columns") or [], key=lambda x: x.get("seq") or 0)]
    return cols


def compare_indexes(idx_a, idx_b):
    dict_a = {i["name"]: i for i in idx_a}
    dict_b = {i["name"]: i for i in idx_b}
    only_a = [i["name"] for i in idx_a if i["name"] not in dict_b]
    only_b = [i["name"] for i in idx_b if i["name"] not in dict_a]
    modified = []
    for name in [i["name"] for i in idx_a if i["name"] in dict_b]:
        a, b = dict_a[name], dict_b[name]
        diffs = []
        if bool(a.get("unique")) != bool(b.get("unique")):
            diffs.append({"property": "unique", "source": a.get("unique"), "target": b.get("unique")})
        sa, sb = _ix_signature(a), _ix_signature(b)
        if sa != sb:
            fmt = lambda s: [f"{c}({p})" if p else c for c, p in s]
            diffs.append({"property": "columns", "source": fmt(sa), "target": fmt(sb)})
        ta = a.get("type") if a.get("type") in ("FULLTEXT", "SPATIAL") else "BTREE/HASH"
        tb = b.get("type") if b.get("type") in ("FULLTEXT", "SPATIAL") else "BTREE/HASH"
        if ta != tb:
            diffs.append({"property": "type", "source": a.get("type"), "target": b.get("type")})
        if diffs:
            modified.append({"index": name, "differences": diffs})
    return {"only_in_source": only_a, "only_in_target": only_b, "modified": modified}


def _fk_sig(fk):
    return (tuple(fk["columns"]), fk["ref_table"], tuple(fk["ref_columns"]), fk["on_update"], fk["on_delete"])


def compare_fks(fk_a, fk_b):
    sa = {_fk_sig(f): f for f in fk_a}
    sb = {_fk_sig(f): f for f in fk_b}
    return {
        "only_in_source": [f for k, f in sa.items() if k not in sb],
        "only_in_target": [f for k, f in sb.items() if k not in sa],
    }


# ---------------------------------------------------------------------------
# Generator SQL
# ---------------------------------------------------------------------------

_NUMERIC_BASES = {"tinyint", "smallint", "mediumint", "int", "integer", "bigint", "decimal", "numeric",
                  "dec", "fixed", "float", "double", "real", "year", "bit", "bool", "boolean"}
_STRING_TYPE = re.compile(r"^(char|varchar|tinytext|text|mediumtext|longtext|enum|set)\b", re.I)
_NUM_LITERAL = re.compile(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?$")
_SAFE_WORD = re.compile(r"^[A-Za-z0-9_]+$")


def sql_str(s):
    """Literal string untuk DDL (sesi dengan backslash-escape aktif)."""
    s = str(s)
    for a, b in (("\\", "\\\\"), ("'", "''"), ("\x00", "\\0"), ("\n", "\\n"), ("\r", "\\r"), ("\x1a", "\\Z")):
        s = s.replace(a, b)
    return f"'{s}'"


def col_to_definition(col):
    """Definisi kolom untuk ADD/MODIFY. None jika kolom generated tanpa ekspresi (harus manual)."""
    extra = col.get("Extra") or ""
    if _is_generated(col):
        expr = (col.get("GenExpr") or "").strip()
        if not expr:
            return None
        kind = "STORED" if ("stored" in extra.lower() or "persistent" in extra.lower()) else "VIRTUAL"
        parts = [q(col["Field"]), col["Type"] or ""]
        if col.get("Collation") and _STRING_TYPE.match(col["Type"] or ""):
            parts.append(f"COLLATE {col['Collation']}")
        parts.append(f"GENERATED ALWAYS AS ({expr}) {kind}")
        if col.get("Null") == "NO":
            parts.append("NOT NULL")
        if col.get("Comment"):
            parts.append(f"COMMENT {sql_str(col['Comment'])}")
        return " ".join(parts)
    ctype = col["Type"] or ""
    base = (re.match(r"[a-z]+", ctype.lower()) or [""])[0]
    parts = [q(col["Field"]), ctype]
    if col.get("Collation") and _STRING_TYPE.match(ctype):
        parts.append(f"COLLATE {col['Collation']}")
    parts.append("NOT NULL" if col.get("Null") == "NO" else "NULL")
    default = col.get("Default")
    auto = "auto_increment" in extra.lower()
    if default is not None:
        d = str(default)
        m = _TS_FUNC.match(d.strip())
        if m:
            parts.append("DEFAULT CURRENT_TIMESTAMP" + (f"({m.group(2)})" if m.group(2) else ""))
        elif base in _NUMERIC_BASES and (_NUM_LITERAL.match(d) or re.fullmatch(r"b'[01]+'", d)):
            parts.append(f"DEFAULT {d}")
        else:
            parts.append(f"DEFAULT {sql_str(d)}")
    elif col.get("Null") == "YES" and not auto:
        parts.append("DEFAULT NULL")
    if auto:
        parts.append("AUTO_INCREMENT")
    m = re.search(r"on update (current_timestamp)(?:\(\s*(\d*)\s*\))?", extra, re.I)
    if m:
        parts.append("ON UPDATE CURRENT_TIMESTAMP" + (f"({m.group(2)})" if m.group(2) else ""))
    if col.get("Comment"):
        parts.append(f"COMMENT {sql_str(col['Comment'])}")
    return " ".join(parts)


def _ix_cols_sql(ix):
    out = []
    for c in sorted(ix.get("columns") or [], key=lambda x: x.get("seq") or 0):
        if not c.get("column"):
            return None  # functional index (MySQL 8) → manual
        s = q(c["column"])
        if c.get("sub_part"):
            s += f"({int(c['sub_part'])})"
        if c.get("collation") == "D":
            s += " DESC"
        out.append(s)
    return ", ".join(out)


def index_add_clause(ix):
    cols = _ix_cols_sql(ix)
    if cols is None:
        return None
    name, itype = ix.get("name") or "idx", (ix.get("type") or "").upper()
    if name.upper() == "PRIMARY":
        return f"ADD PRIMARY KEY ({cols})"
    if itype == "FULLTEXT":
        return f"ADD FULLTEXT INDEX {q(name)} ({cols})"
    if itype == "SPATIAL":
        return f"ADD SPATIAL INDEX {q(name)} ({cols})"
    uniq = "UNIQUE " if ix.get("unique") else ""
    using = " USING HASH" if itype == "HASH" else ""
    return f"ADD {uniq}INDEX {q(name)} ({cols}){using}"


def fk_add_clause(fk, taken_names):
    name = fk["name"]
    cons = f"CONSTRAINT {q(name)} " if name not in taken_names else ""
    s = (f"ADD {cons}FOREIGN KEY ({', '.join(q(c) for c in fk['columns'])}) "
         f"REFERENCES {q(fk['ref_table'])} ({', '.join(q(c) for c in fk['ref_columns'])})")
    if fk["on_delete"] != "RESTRICT":
        s += f" ON DELETE {fk['on_delete']}"
    if fk["on_update"] != "RESTRICT":
        s += f" ON UPDATE {fk['on_update']}"
    return s


def _stmt(table, kind, sql):
    return {"table": table, "kind": kind, "sql": sql, "manual": False, "additive": sqlguard.classify(sql)}


def _manual(table, text):
    return {"table": table, "kind": "MANUAL", "sql": "-- " + text.replace("\n", "\n-- "), "manual": True, "additive": False}


def generate_alter_items(table, ref_cols, dst_cols, only_ref, only_dst, modified_names,
                         ref_idx, dst_idx, idx_diff, fk_diff_ref_only, fk_diff_dst_only,
                         meta, dst_fk_names):
    """
    Buat Destination mengikuti Reference. Setiap item = satu statement (atau catatan manual).
    """
    items = []
    ref_map = {c["Field"]: c for c in ref_cols}
    ref_prev = {c["Field"]: (ref_cols[i - 1]["Field"] if i else None) for i, c in enumerate(ref_cols)}
    existing = {c["Field"] for c in dst_cols}
    T = q(table)

    for name in only_ref:
        col = ref_map[name]
        d = col_to_definition(col)
        if d is None:
            items.append(_manual(table, f"Kolom generated `{name}` — salin definisinya dari SHOW CREATE TABLE tabel acuan."))
            continue
        prev = ref_prev.get(name)
        pos = " FIRST" if prev is None else (f" AFTER {q(prev)}" if prev in existing else "")
        items.append(_stmt(table, "ADD COLUMN", f"ALTER TABLE {T} ADD COLUMN {d}{pos};"))
        existing.add(name)
    for name in only_dst:
        items.append(_manual(table, f"Kolom `{name}` hanya ada di sisi yang disamakan. Jika ingin dihapus (HATI-HATI, data hilang): ALTER TABLE {T} DROP COLUMN {q(name)};"))
    for name in modified_names:
        d = col_to_definition(ref_map[name])
        if d is None:
            items.append(_manual(table, f"Kolom generated `{name}` berbeda — ubah manual."))
        else:
            items.append(_stmt(table, "MODIFY COLUMN", f"ALTER TABLE {T} MODIFY COLUMN {d};"))

    if idx_diff is not None:
        ref_by = {i["name"]: i for i in ref_idx}
        dst_names = {i["name"] for i in dst_idx}
        for ix in ref_idx:
            if ix["name"] not in dst_names:
                clause = index_add_clause(ix)
                if clause:
                    items.append(_stmt(table, "ADD INDEX", f"ALTER TABLE {T} {clause};"))
                else:
                    items.append(_manual(table, f"Index fungsional `{ix['name']}` — buat manual."))
        for m in idx_diff["modified"]:
            ix = ref_by.get(m["index"])
            clause = index_add_clause(ix) if ix else None
            if not clause:
                items.append(_manual(table, f"Index `{m['index']}` berbeda — ubah manual."))
                continue
            drop = "DROP PRIMARY KEY" if m["index"].upper() == "PRIMARY" else f"DROP INDEX {q(m['index'])}"
            items.append(_stmt(table, "REPLACE INDEX", f"ALTER TABLE {T} {drop}, {clause};"))
        for name in [n for n in (i["name"] for i in dst_idx) if n not in ref_by]:
            items.append(_manual(table, f"Index `{name}` hanya ada di sisi yang disamakan. Hapus manual jika perlu: ALTER TABLE {T} DROP INDEX {q(name)};"))

    taken = set(dst_fk_names)
    dst_only_names = {f["name"] for f in fk_diff_dst_only}
    replaced = set()
    for fk in fk_diff_ref_only:
        if fk["name"] in dst_only_names:
            # FK bernama sama tetapi definisinya berbeda: ganti (DROP lalu ADD), jangan membuat duplikat.
            replaced.add(fk["name"])
            items.append(_stmt(table, "REPLACE FOREIGN KEY", f"ALTER TABLE {T} DROP FOREIGN KEY {q(fk['name'])};"))
            clause = fk_add_clause(fk, taken - {fk["name"]})
            items.append({"table": table, "kind": "REPLACE FOREIGN KEY", "sql": f"ALTER TABLE {T} {clause};",
                          "manual": False, "additive": False})
            continue
        items.append(_stmt(table, "ADD FOREIGN KEY", f"ALTER TABLE {T} {fk_add_clause(fk, taken)};"))
        taken.add(fk["name"])
    for fk in fk_diff_dst_only:
        if fk["name"] in replaced:
            continue
        items.append(_manual(table, f"Foreign key `{fk['name']}` hanya ada di sisi yang disamakan: ALTER TABLE {T} DROP FOREIGN KEY {q(fk['name'])};"))

    for m in meta:
        val = m["ref"]
        if val and _SAFE_WORD.match(val):
            if m["property"] == "ENGINE":
                items.append(_stmt(table, "ENGINE", f"ALTER TABLE {T} ENGINE={val};"))
            elif m["property"] == "COLLATION":
                items.append(_stmt(table, "COLLATION", f"ALTER TABLE {T} COLLATE={val};"))
            elif m["property"] == "ROW_FORMAT":
                val = "DEFAULT" if val == "(default)" else val
                items.append(_stmt(table, "ROW_FORMAT", f"ALTER TABLE {T} ROW_FORMAT={val};"))
        if m["property"] == "COMMENT":
            items.append(_stmt(table, "COMMENT", f"ALTER TABLE {T} COMMENT={sql_str(m['ref'] or '')};"))
    return items


_AUTO_INC_OPT = re.compile(r"\s+AUTO_INCREMENT=\d+", re.I)


def prepare_create(create_sql):
    """CREATE TABLE siap-eksekusi dari SHOW CREATE TABLE: buka komentar eksekutabel, buang counter AUTO_INCREMENT."""
    s = sqlguard.unwrap_executable_comments(create_sql or "").rstrip().rstrip(";")
    s = _AUTO_INC_OPT.sub("", s)
    return s + ";"


# ---------------------------------------------------------------------------
# Halaman & endpoint
# ---------------------------------------------------------------------------

@app.context_processor
def _asset_versioning():
    """url_for('static', ...) otomatis diberi ?v=<mtime> agar browser tidak memakai CSS/JS lama setelah update."""
    def static_url(filename):
        path = os.path.join(app.static_folder, filename)
        try:
            v = int(os.path.getmtime(path))
        except OSError:
            v = 0
        return url_for("static", filename=filename, v=v)
    return {"static_url": static_url}


@app.route("/")
def index():
    return render_template("index.html", csrf_token=CSRF_TOKEN)


@app.route("/api/list-databases", methods=["POST"])
def list_databases():
    data = body()
    with closing(connect(data, need_db=False, read_timeout=30)) as conn:
        with conn.cursor() as cur:
            cur.execute("SHOW DATABASES")
            rows = cur.fetchall()
            key = list(rows[0].keys())[0] if rows else "Database"
            dbs = sorted(r[key] for r in rows)
            cur.execute("SELECT VERSION() AS v")
            ver = cur.fetchone()["v"]
    system = {"information_schema", "mysql", "performance_schema", "sys"}
    user_dbs = [d for d in dbs if d not in system]
    ordered = user_dbs + [d for d in dbs if d in system]
    return jsonify({
        "success": True, "databases": ordered, "user_databases": user_dbs, "version": ver,
        "message": f"Ditemukan {len(user_dbs)} database (total {len(ordered)}). MySQL {ver}",
    })


def _table_detail_item(conn, t, status, include_row_count, include_indexes):
    cols = get_table_columns(conn, t)
    st = status.get(t, {})
    item = {
        "table": t, "columns": cols, "column_count": len(cols),
        "create_sql": get_create_table(conn, t), "engine": st.get("ENGINE"),
        "collation": st.get("TABLE_COLLATION"), "comment": st.get("TABLE_COMMENT"),
    }
    if include_row_count:
        item["row_count"] = get_row_count(conn, t)
    if include_indexes:
        item["indexes"] = get_table_indexes(conn, t)
    return item


@app.route("/api/compare", methods=["POST"])
def compare():
    data = body()
    include_row_count = bool(data.get("include_row_count", False))
    include_indexes = bool(data.get("include_indexes", True))
    include_fks = bool(data.get("include_fks", True))
    src_info, tgt_info = data.get("source"), data.get("target")
    db_s, db_t = clean_conn(src_info)["database"], clean_conn(tgt_info)["database"]

    with closing(connect(src_info)) as conn_s, closing(connect(tgt_info)) as conn_t:
        tables_s, tables_t = set(get_tables(conn_s)), set(get_tables(conn_t))
        views_s, views_t = set(get_views(conn_s)), set(get_views(conn_t))
        status_s, status_t = get_all_table_status(conn_s), get_all_table_status(conn_t)
        fks_s = get_foreign_keys(conn_s) if include_fks else {}
        fks_t = get_foreign_keys(conn_t) if include_fks else {}
        all_fk_names_t = {f["name"] for fl in fks_t.values() for f in fl}
        all_fk_names_s = {f["name"] for fl in fks_s.values() for f in fl}

        only_in_source = sorted(tables_s - tables_t)
        only_in_target = sorted(tables_t - tables_s)
        common_tables = sorted(tables_s & tables_t)

        detail_only_in_source = [_table_detail_item(conn_s, t, status_s, include_row_count, include_indexes) for t in only_in_source]
        detail_only_in_target = [_table_detail_item(conn_t, t, status_t, include_row_count, include_indexes) for t in only_in_target]

        table_diffs, identical_tables = [], []
        for t in common_tables:
            cols_s, cols_t = get_table_columns(conn_s, t), get_table_columns(conn_t, t)
            diff = compare_columns(cols_s, cols_t)
            idx_s = idx_t = []
            idx_diff = None
            if include_indexes:
                idx_s, idx_t = get_table_indexes(conn_s, t), get_table_indexes(conn_t, t)
                idx_diff = compare_indexes(idx_s, idx_t)
            fk_diff = compare_fks(fks_s.get(t, []), fks_t.get(t, [])) if include_fks else {"only_in_source": [], "only_in_target": []}

            ss, st = status_s.get(t, {}), status_t.get(t, {})
            meta_diff = []
            if (ss.get("ENGINE") or "") != (st.get("ENGINE") or ""):
                meta_diff.append({"property": "ENGINE", "source": ss.get("ENGINE"), "target": st.get("ENGINE")})
            if (ss.get("TABLE_COLLATION") or "") != (st.get("TABLE_COLLATION") or ""):
                meta_diff.append({"property": "COLLATION", "source": ss.get("TABLE_COLLATION"), "target": st.get("TABLE_COLLATION")})
            if (ss.get("TABLE_COMMENT") or "") != (st.get("TABLE_COMMENT") or ""):
                meta_diff.append({"property": "COMMENT", "source": ss.get("TABLE_COMMENT") or "", "target": st.get("TABLE_COMMENT") or ""})
            rf_s, rf_t = _row_format(ss.get("CREATE_OPTIONS")), _row_format(st.get("CREATE_OPTIONS"))
            if rf_s != rf_t:
                meta_diff.append({"property": "ROW_FORMAT", "source": rf_s or "(default)", "target": rf_t or "(default)"})

            has_col = bool(diff["only_in_source"] or diff["only_in_target"] or diff["modified"])
            has_idx = bool(idx_diff and (idx_diff["only_in_source"] or idx_diff["only_in_target"] or idx_diff["modified"]))
            has_fk = bool(fk_diff["only_in_source"] or fk_diff["only_in_target"])
            if not (has_col or has_idx or has_fk or meta_diff):
                identical_tables.append(t)
                continue

            mod_names = [m["column"] for m in diff["modified"]]
            # source → target : Reference = source
            s2t = generate_alter_items(
                t, cols_s, cols_t, diff["only_in_source"], diff["only_in_target"], mod_names,
                idx_s, idx_t, idx_diff, fk_diff["only_in_source"], fk_diff["only_in_target"],
                [{"property": m["property"], "ref": m["source"]} for m in meta_diff], all_fk_names_t)
            # target → source : Reference = target
            idx_diff_rev = None
            if idx_diff is not None:
                idx_diff_rev = {"only_in_source": idx_diff["only_in_target"], "only_in_target": idx_diff["only_in_source"], "modified": idx_diff["modified"]}
            t2s = generate_alter_items(
                t, cols_t, cols_s, diff["only_in_target"], diff["only_in_source"], mod_names,
                idx_t, idx_s, idx_diff_rev, fk_diff["only_in_target"], fk_diff["only_in_source"],
                [{"property": m["property"], "ref": m["target"]} for m in meta_diff], all_fk_names_s)
            item = {
                "table": t, "diff": diff, "index_diff": idx_diff, "fk_diff": fk_diff, "meta_diff": meta_diff,
                "alter_source_to_target": s2t, "alter_target_to_source": t2s,
                "engine_source": ss.get("ENGINE"), "engine_target": st.get("ENGINE"),
            }
            if include_row_count:
                item["row_count_source"] = get_row_count(conn_s, t)
                item["row_count_target"] = get_row_count(conn_t, t)
            table_diffs.append(item)

        def_s, def_t = get_view_definitions(conn_s, db_s), get_view_definitions(conn_t, db_t)

    common_views = sorted(views_s & views_t)
    changed_views = [v for v in common_views if def_s.get(v) and def_t.get(v) and def_s[v] != def_t[v]]

    def build_statements(direction):
        items = []
        if direction == "source_to_target":
            creates, key = detail_only_in_source, "alter_source_to_target"
        else:
            creates, key = detail_only_in_target, "alter_target_to_source"
        for t in creates:
            items.append({"id": "create-" + t["table"], "table": t["table"], "kind": "CREATE",
                          "sql": prepare_create(t["create_sql"]), "checked": True, "additive": True})
        for td in table_diffs:
            for i, a in enumerate(td[key]):
                if a["manual"]:
                    continue
                items.append({"id": f"alter-{td['table']}-{i}", "table": td["table"], "kind": a["kind"],
                              "sql": a["sql"], "checked": True, "additive": a["additive"]})
        return items

    def build_notes(direction):
        key = "alter_source_to_target" if direction == "source_to_target" else "alter_target_to_source"
        return [{"table": td["table"], "text": a["sql"].replace("-- ", "", 1).replace("\n-- ", "\n")}
                for td in table_diffs for a in td[key] if a["manual"]]

    result = {
        "success": True,
        "compared_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "source_table_count": len(tables_s), "target_table_count": len(tables_t),
            "common_tables": len(common_tables), "identical_tables": len(identical_tables),
            "only_in_source_count": len(only_in_source), "only_in_target_count": len(only_in_target),
            "tables_with_diff_count": len(table_diffs),
            "source_view_count": len(views_s), "target_view_count": len(views_t),
            "only_views_source": len(views_s - views_t), "only_views_target": len(views_t - views_s),
            "changed_views": len(changed_views),
        },
        "only_in_source": only_in_source, "only_in_target": only_in_target,
        "detail_only_in_source": detail_only_in_source, "detail_only_in_target": detail_only_in_target,
        "table_diffs": table_diffs, "identical_tables": identical_tables, "common_tables": common_tables,
        "views": {"only_in_source": sorted(views_s - views_t), "only_in_target": sorted(views_t - views_s),
                  "common": common_views, "changed": changed_views},
        "statements_source_to_target": build_statements("source_to_target"),
        "statements_target_to_source": build_statements("target_to_source"),
        "notes_source_to_target": build_notes("source_to_target"),
        "notes_target_to_source": build_notes("target_to_source"),
    }
    return jsonify(result)


@app.route("/api/table-detail", methods=["POST"])
def table_detail():
    data = body()
    side = "source" if data.get("side") == "source" else "target"
    table = str(data.get("table") or "")
    if not table:
        raise ApiError("Nama tabel wajib diisi")
    with closing(connect(data.get(side))) as conn:
        if table not in get_tables(conn):
            raise ApiError("Tabel tidak ditemukan")
        return jsonify({
            "success": True, "table": table, "columns": get_table_columns(conn, table),
            "create_sql": get_create_table(conn, table), "indexes": get_table_indexes(conn, table),
            "status": get_all_table_status(conn).get(table, {}),
        })


# --- Eksekusi DDL -----------------------------------------------------------

@app.route("/api/execute-one", methods=["POST"])
def execute_one():
    """
    Jalankan satu/beberapa statement DDL ke database tujuan.
    SQL divalidasi sqlguard (allowlist). Mode Aman (default) DIPAKSA di server.
    FOREIGN_KEY_CHECKS dimatikan per-koneksi agar urutan CREATE TABLE tidak bermasalah.
    """
    data = body()
    side = "source" if data.get("side") == "source" else "target"
    safe_mode = data.get("safe_mode", True) is not False
    if not data.get(side):
        raise ApiError("Koneksi tidak ada")
    try:
        plan = sqlguard.prepare_script(str(data.get("sql") or ""), safe_mode=safe_mode)
    except sqlguard.SQLGuardError as e:
        raise ApiError(f"Ditolak: {e}", 400)
    run = [p for p in plan if p["kind"] != "SET"]
    with closing(connect(data[side], writable=True, fk_checks=False,
                       mode_add=("NO_AUTO_VALUE_ON_ZERO",), mode_remove=("NO_BACKSLASH_ESCAPES", "ANSI_QUOTES"))) as conn:
        conn.autocommit(True)
        with conn.cursor() as cur:
            for p in run:
                cur.execute(p["sql"])
    return jsonify({"success": True, "message": f"Berhasil dijalankan ({len(run)} statement)", "statements": len(run)})


# --- Data sync --------------------------------------------------------------

def _norm_key(v):
    if isinstance(v, str):
        return v.casefold().rstrip(" ")
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return v


def _norm_tuple(t):
    return tuple(_norm_key(v) for v in t)


def _in_clause(pk, n):
    if len(pk) == 1:
        return f"{q(pk[0])} IN ({','.join(['%s'] * n)})"
    one = "(" + ",".join(["%s"] * len(pk)) + ")"
    return f"({', '.join(q(c) for c in pk)}) IN ({','.join([one] * n)})"


def _flat(keys):
    return [v for k in keys for v in k]


def data_columns(conn_s, conn_t, table):
    cs, ct = get_table_columns(conn_s, table), get_table_columns(conn_t, table)

    def gen(c):
        e = (c.get("Extra") or "").lower()
        return "generated" in e or "persistent" in e

    tgt = {c["Field"]: c for c in ct}
    used, skipped = [], []
    for c in cs:
        f = c["Field"]
        if f not in tgt:
            skipped.append({"column": f, "reason": "tidak ada di Target"})
        elif gen(c) or gen(tgt[f]):
            skipped.append({"column": f, "reason": "kolom generated"})
        else:
            used.append(f)
    return used, skipped


def scan_missing(conn_s, conn_t, table, pk, cols, max_rows, stats, scan_limit=2_000_000, chunk=1000):
    """
    Generator: baris yang ada di Source tapi tidak di Target (berdasarkan PRIMARY KEY).
    Keyset-pagination di Source (ORDER BY pk) + pengecekan IN() ke Target per chunk,
    sehingga akurat untuk tabel berapa pun (tidak ada LIMIT acak seperti sebelumnya).
    """
    tq = q(table)
    pk_sql = ", ".join(q(c) for c in pk)
    col_sql = ", ".join(q(c) for c in cols)
    last = None
    stats.update(scanned=0, found=0, truncated=False, scan_capped=False)
    while True:
        if last is None:
            where, params = "", []
        elif len(pk) == 1:
            where, params = f"WHERE {q(pk[0])} > %s", [last[0]]
        else:
            where, params = f"WHERE ({pk_sql}) > ({','.join(['%s'] * len(pk))})", list(last)
        with conn_s.cursor() as cur:
            cur.execute(f"SELECT {pk_sql} FROM {tq} {where} ORDER BY {pk_sql} LIMIT {int(chunk)}", params)
            keys = [tuple(r[c] for c in pk) for r in cur.fetchall()]
        if not keys:
            return
        stats["scanned"] += len(keys)
        with conn_t.cursor() as cur:
            cur.execute(f"SELECT {pk_sql} FROM {tq} WHERE {_in_clause(pk, len(keys))}", _flat(keys))
            present = {_norm_tuple(tuple(r[c] for c in pk)) for r in cur.fetchall()}
        missing = [k for k in keys if _norm_tuple(k) not in present]
        room = max_rows - stats["found"]
        if len(missing) > room:
            missing, stats["truncated"] = missing[:room], True
        rows = []
        if missing:
            with conn_s.cursor() as cur:
                cur.execute(f"SELECT {col_sql} FROM {tq} WHERE {_in_clause(pk, len(missing))} ORDER BY {pk_sql}", _flat(missing))
                rows = [tuple(r[c] for c in cols) for r in cur.fetchall()]
            stats["found"] += len(rows)
            yield rows
        if stats["truncated"] or stats["found"] >= max_rows:
            stats["truncated"] = stats["truncated"] or len(keys) == chunk
            return
        if len(keys) < chunk:
            return
        if stats["scanned"] >= scan_limit:
            stats["scan_capped"] = True
            return
        last = keys[-1]


def _data_params(data):
    table = str(data.get("table") or "")
    if not table:
        raise ApiError("Nama tabel wajib")
    try:
        max_rows = max(1, min(int(data.get("max_rows") or 500), 20000))
    except (TypeError, ValueError):
        raise ApiError("max_rows harus angka")
    return table, max_rows


def _prepare_table(conn_s, conn_t, table):
    if table not in get_tables(conn_s):
        raise ApiError(f"Tabel `{table}` tidak ada di Source")
    if table not in get_tables(conn_t):
        raise ApiError(f"Tabel `{table}` tidak ada di Target — sinkronkan struktur dulu")
    pk = get_primary_key_columns(conn_s, table)
    if not pk:
        raise ApiError(f"Tabel `{table}` tidak punya PRIMARY KEY — data sync dilewati (aman).")
    cols, skipped = data_columns(conn_s, conn_t, table)
    if not set(pk) <= set(cols):
        raise ApiError(f"Kolom PRIMARY KEY `{table}` tidak lengkap di Target")
    return pk, cols, skipped


@app.route("/api/data-overview", methods=["POST"])
def data_overview():
    data = body()
    exact = bool(data.get("exact", False))
    want = set(data.get("tables") or [])
    with closing(connect(data.get("source"))) as conn_s, closing(connect(data.get("target"))) as conn_t:
        common = sorted(set(get_tables(conn_s)) & set(get_tables(conn_t)))
        if want:
            common = [t for t in common if t in want]
        st_s, st_t = get_all_table_status(conn_s), get_all_table_status(conn_t)
        pks_s = _all_primary_keys(conn_s)
        pks_t = _all_primary_keys(conn_t)
        items = []
        for t in common:
            pk = pks_s.get(t) or pks_t.get(t) or []
            rc_s = get_row_count(conn_s, t) if exact else (st_s.get(t, {}).get("TABLE_ROWS"))
            rc_t = get_row_count(conn_t, t) if exact else (st_t.get(t, {}).get("TABLE_ROWS"))
            low = t.lower()
            items.append({
                "table": t, "pk": pk, "rows_source": rc_s, "rows_target": rc_t,
                "diff": (rc_s or 0) - (rc_t or 0), "has_pk": bool(pk), "approx": not exact,
                "large": (rc_s or 0) > 10000 or (rc_t or 0) > 10000,
                "risky": low in KHANZA_RISKY_TABLES or low.startswith(RISKY_PREFIXES),
            })
    return jsonify({"success": True, "tables": items, "count": len(items), "approx": not exact})


def _all_primary_keys(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION FROM information_schema.KEY_COLUMN_USAGE "
            "WHERE TABLE_SCHEMA = DATABASE() AND CONSTRAINT_NAME = 'PRIMARY' ORDER BY TABLE_NAME, ORDINAL_POSITION"
        )
        out = {}
        for r in cur.fetchall():
            out.setdefault(r["TABLE_NAME"], []).append(r["COLUMN_NAME"])
        return out


@app.route("/api/data-diff", methods=["POST"])
def data_diff():
    """Pratinjau baris yang ada di Source tapi belum di Target (tidak menulis apa pun)."""
    data = body()
    table, max_rows = _data_params(data)
    with closing(connect(data.get("source"))) as conn_s, closing(connect(data.get("target"))) as conn_t:
        pk, cols, skipped = _prepare_table(conn_s, conn_t, table)
        stats, preview, sample = {}, [], []
        col_sql = ", ".join(q(c) for c in cols)
        for rows in scan_missing(conn_s, conn_t, table, pk, cols, max_rows, stats):
            for r in rows:
                if len(preview) < 50:
                    vals = ", ".join(conn_s.escape(v) for v in r)
                    preview.append(f"INSERT INTO {q(table)} ({col_sql}) VALUES ({vals});")
                if len(sample) < 20:
                    sample.append({c: str(r[cols.index(c)]) for c in pk})
    return jsonify({
        "success": True, "table": table, "pk": pk, "missing_count": stats.get("found", 0),
        "scanned_source": stats.get("scanned", 0), "inserts": preview, "sample_keys": sample,
        "truncated": stats.get("truncated", False), "scan_capped": stats.get("scan_capped", False),
        "skipped_columns": skipped,
    })


@app.route("/api/data-sync", methods=["POST"])
def data_sync():
    """
    INSERT baris yang hilang ke Target. Server menghitung sendiri barisnya dari Source
    (browser TIDAK bisa menyuntikkan SQL). Hanya INSERT — tidak ada UPDATE/DELETE.
    """
    data = body()
    table, max_rows = _data_params(data)
    dry = bool(data.get("dry_run", False))
    with closing(connect(data.get("source"))) as conn_s, \
            closing(connect(data.get("target"), writable=not dry, mode_add=("NO_AUTO_VALUE_ON_ZERO",))) as conn_t:
        pk, cols, skipped = _prepare_table(conn_s, conn_t, table)
        stats, ok, dup, errors = {}, 0, 0, []
        ins = f"INSERT INTO {q(table)} ({', '.join(q(c) for c in cols)}) VALUES ({','.join(['%s'] * len(cols))})"
        for rows in scan_missing(conn_s, conn_t, table, pk, cols, max_rows, stats):
            if dry:
                ok += len(rows)
                continue
            try:
                with conn_t.cursor() as cur:
                    cur.executemany(ins, rows)
                conn_t.commit()
                ok += len(rows)
            except pymysql.MySQLError:
                conn_t.rollback()
                for r in rows:  # isolasi baris bermasalah
                    try:
                        with conn_t.cursor() as cur:
                            cur.execute(ins, r)
                        conn_t.commit()
                        ok += 1
                    except pymysql.MySQLError as ex:
                        conn_t.rollback()
                        if ex.args and ex.args[0] == 1062:
                            dup += 1
                        else:
                            errors.append({"key": {c: str(r[cols.index(c)]) for c in pk}, "message": str(ex)})
    err = len(errors)
    verb = "Pratinjau" if dry else "Data sync"
    return jsonify({
        "success": err == 0, "table": table, "dry_run": dry,
        "message": f"{verb} `{table}`: {'akan disisipkan' if dry else 'berhasil'} {ok}, duplikat dilewati {dup}, gagal {err}",
        "success_count": ok, "duplicate_count": dup, "error_count": err, "errors": errors[:50],
        "missing_count": stats.get("found", 0), "scanned_source": stats.get("scanned", 0),
        "truncated": stats.get("truncated", False), "scan_capped": stats.get("scan_capped", False),
        "skipped_columns": skipped,
    })


# --- Backup -----------------------------------------------------------------

def _safe_filename(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:80] or "db"


def _stream_file_then_delete(path, chunk=1 << 20):
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                yield b
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _python_dump(info, include_data):
    """Fallback tanpa mysqldump: streaming (SSCursor), tanpa batas baris diam-diam."""
    conn = connect(info)
    try:
        yield "-- Backup SinkronKhanza (fallback pymysql: HANYA TABEL — tanpa view/trigger/routine/event)\n"
        yield f"-- Database: {info.get('database')}\n-- Waktu: {datetime.now().isoformat(timespec='seconds')}\n"
        yield "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n\n"
        for t in get_tables(conn):
            try:
                yield f"DROP TABLE IF EXISTS {q(t)};\n{get_create_table(conn, t)};\n\n"
                if include_data:
                    with conn.cursor(SSCursor) as cur:
                        cur.execute(f"SELECT * FROM {q(t)}")
                        cols = ", ".join(q(d[0]) for d in cur.description)
                        batch = []
                        for row in cur:
                            batch.append("(" + ", ".join(conn.escape(v) for v in row) + ")")
                            if len(batch) >= 200:
                                yield f"INSERT INTO {q(t)} ({cols}) VALUES\n" + ",\n".join(batch) + ";\n"
                                batch = []
                        if batch:
                            yield f"INSERT INTO {q(t)} ({cols}) VALUES\n" + ",\n".join(batch) + ";\n"
                        yield "\n"
            except Exception as te:  # satu tabel gagal tidak menghentikan sisanya, tetapi ditandai jelas
                yield f"-- !!! ERROR tabel {t}: {str(te)[:300]!r} — BACKUP TIDAK LENGKAP\n"
        yield "SET FOREIGN_KEY_CHECKS=1;\nSET UNIQUE_CHECKS=1;\n-- Dump completed\n"
    finally:
        conn.close()


@app.route("/api/backup", methods=["POST"])
def backup_database():
    data = body()
    c = clean_conn(data)
    include_data = not bool(data.get("structure_only", False)) and bool(data.get("include_data", True))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backup_{_safe_filename(c['database'])}_{stamp}.sql"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"}

    mysqldump = shutil.which("mysqldump") or shutil.which("mariadb-dump")
    mysqldump_error = None
    if mysqldump:
        fd, path = tempfile.mkstemp(prefix="dbsync_", suffix=".sql")
        os.close(fd)
        os.chmod(path, 0o600)
        base = [
            mysqldump, f"--host={c['host']}", f"--port={c['port']}", f"--user={c['user']}",
            "--protocol=TCP", "--single-transaction", "--quick", "--routines", "--triggers", "--events",
            "--hex-blob", "--default-character-set=utf8mb4", f"--result-file={path}",
        ]
        if not include_data:
            base.append("--no-data")
        optional = ["--set-gtid-purged=OFF", "--column-statistics=0"]
        env = dict(os.environ, MYSQL_PWD=c["password"]) if c["password"] else dict(os.environ)
        env.pop("MYSQL_HOST", None)
        flags = list(optional)
        proc = None
        for _ in range(3):
            proc = subprocess.run(base + flags + ["--", c["database"]], capture_output=True, env=env, timeout=3600)
            err = (proc.stderr or b"").decode("utf-8", "replace")
            if proc.returncode == 0:
                break
            # opsi tidak didukung (MariaDB / versi lama) → buang lalu ulangi
            dropped = False
            for f in list(flags):
                if f.split("=")[0].lstrip("-") in err:
                    flags.remove(f)
                    dropped = True
            if not dropped:
                break
        if proc is not None and proc.returncode == 0:
            headers["X-Backup-Method"] = "mysqldump"
            return Response(_stream_file_then_delete(path), mimetype="application/sql", headers=headers)
        mysqldump_error = (proc.stderr or b"").decode("utf-8", "replace")[:300] if proc else "gagal"
        try:
            os.remove(path)
        except OSError:
            pass

    # fallback: pastikan koneksi valid sebelum mulai streaming (supaya error jadi JSON, bukan file rusak)
    connect(data).close()
    headers["X-Backup-Method"] = "pymysql-fallback"
    if mysqldump_error:
        headers["X-Backup-Note"] = re.sub(r"[^\x20-\x7e]", " ", mysqldump_error)[:200]
    return Response(_python_dump(data, include_data), mimetype="application/sql", headers=headers)


# ---------------------------------------------------------------------------

def _open_browser_when_ready(url, host, port):
    """Buka browser bawaan setelah server benar-benar menerima koneksi (maks. 15 detik)."""
    import socket
    import threading
    import time
    import webbrowser

    def worker():
        for _ in range(60):
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            return
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()


def main():
    if ACCESS_PASSWORD == "" and not is_loopback(BIND_HOST):
        sys.exit("DITOLAK: DBSYNC_HOST bukan loopback tetapi DBSYNC_PASSWORD kosong.\n"
                 "Aplikasi ini bisa menjalankan DDL ke database Anda — set DBSYNC_PASSWORD bila ingin diakses dari jaringan.")
    if DEBUG and not is_loopback(BIND_HOST):
        sys.exit("DITOLAK: DBSYNC_DEBUG=1 hanya boleh di loopback (debugger Werkzeug = eksekusi kode jarak jauh).")
    url_host = BIND_HOST if BIND_HOST not in ("0.0.0.0", "::") else "127.0.0.1"
    line = "=" * 62
    print(line)
    print("  SinkronKhanza - pembanding & penyinkron skema SIMRS Khanza")
    print("  by Iqbal Gilang Permana, S.Kom")
    print(line)
    print(f"  Buka di browser : http://{url_host}:{BIND_PORT}")
    print("  Mode debug      : " + ("AKTIF (hanya untuk pengembangan)" if DEBUG else "mati (normal)"))
    if ACCESS_PASSWORD:
        print("  Autentikasi     : Basic Auth aktif (user bebas, password = DBSYNC_PASSWORD)")
    print(line)
    print("  WhatsApp : 0851-5670-4337  (wa.me/6285156704337)")
    print("  Donasi   : Bank Jago 103795214092  (pilihan bank ada di aplikasi)")
    print(line)
    print("  Tekan Ctrl+C untuk berhenti.\n")
    try:  # sembunyikan banner bawaan Flask yang membingungkan
        from flask import cli as _flask_cli
        _flask_cli.show_server_banner = lambda *a, **k: None
    except Exception:
        pass
    if os.environ.get("DBSYNC_OPEN_BROWSER", "1") != "0" and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        _open_browser_when_ready(f"http://{url_host}:{BIND_PORT}", url_host, BIND_PORT)
    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG, threaded=True)


if __name__ == "__main__":
    main()

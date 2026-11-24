"""Core 1C:Enterprise 8 reader, caching, binary container, and .1CD utilities."""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from typing import Any

import onec_dtools

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

CLASS_NAMES: dict[str, str] = {
    "9cd510cd-abfc-11d4-9434-004095e12fc7": "Конфигурация",
    "9cd510ce-abfc-11d4-9434-004095e12fc7": "Языки",
    "37f2fa9a-b276-11d4-9435-004095e12fc7": "Подсистемы",
    "0fe48980-252d-11d6-a3c7-0050bae0a776": "Общие модули",
    "11bdaf85-d5ad-4d91-bb24-aa0eee139052": "Регламентные задания",
    "09736b02-9cac-4e3f-b4f7-d3e9576ab948": "Роли",
    "07ee8426-87f1-11d5-b99c-0050bae0a95d": "Общие формы",
    "1c57eabe-7349-44b3-b1de-ebfeab67b47d": "Общие команды",
    "2f1a5187-fb0e-4b05-9489-dc5dd6412348": "Группы команд",
    "0c89c792-16c3-11d5-b96b-0050bae0a95d": "Общие макеты",
    "7dcd43d9-aca5-4926-b549-1842e6a4e8cf": "Общие картинки",
    "3e5404af-6ef8-4c73-ad11-91bd2dfac4c8": "Стили",
    "af547940-3268-434f-a3e7-e47d6d2638c3": "Функциональные опции",
    "15794563-ccec-41f6-a83c-ec5f7b9a5bc1": "Общие реквизиты",
    "cc9df798-7c94-4616-97d2-7aa0b7bc515e": "Пакеты XDTO",
    "c045099e-13b9-4fb6-9d50-fca00202971e": "Определяемые типы",
    "3e7bfcc0-067d-11d6-a3c7-0050bae0a776": "Критерии отбора",
    "857c4a91-e5f4-4fac-86ec-787626f1c108": "Планы обмена",
    "0195e80c-b157-11d4-9435-004095e12fc7": "Константы",
    "cf4abea6-37b2-11d4-940f-008048da11f9": "Справочники",
    "061d872a-5787-460e-95ac-ed74ea3a3e84": "Документы",
    "36a8e346-9aaa-4af9-bdbd-83be3c177977": "Нумераторы документов",
    "4612bd75-71b7-4a5c-8cc5-2b0b65f9fa0d": "Журналы документов",
    "f6a80749-5ad7-400b-8519-39dc5dff2542": "Перечисления",
    "631b75a0-29e2-11d6-a3c7-0050bae0a776": "Отчеты",
    "bf845118-327b-4682-b5c6-285d2a0eb296": "Обработки",
    "82a1b659-b220-4d94-a9bd-14d757b95a48": "Планы видов характеристик",
    "238e7e88-3c5f-48b2-8a3b-81ebbecb20ed": "Планы счетов",
    "30b100d6-b29f-47ac-aec7-cb8ca8a54767": "Планы видов расчета",
    "13134201-f60b-11d5-a3c7-0050bae0a776": "Регистры сведений",
    "b64d9a40-1642-11d6-a3c7-0050bae0a776": "Регистры накопления",
    "2deed9b8-0056-4ffe-a473-c20a6c32a0bc": "Регистры бухгалтерии",
    "f2de87a8-64e5-45eb-a22d-b3aedab050e7": "Регистры расчета",
    "fcd3404e-1523-48ce-9bc0-ecdb822684a1": "Бизнес-процессы",
    "3e63355c-1378-4953-be9b-1deb5fb6bec5": "Задачи",
}

CONTAINER_MAGIC = b"\xff\xff\xff\x7f"
CONTAINER_EXTS = {".cf", ".cfe", ".epf", ".ert", ".efd"}
BSL_KEYWORDS = (
    "Процедура ",
    "Функция ",
    "&НаСервере",
    "&НаКлиенте",
    "Procedure ",
    "Function ",
)


def clean_text(value: Any) -> str:
    """Normalizes bytes/text and removes terminal-unsafe control characters."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return CONTROL_CHARS_RE.sub("", str(value))


def decompress_1c(raw: bytes) -> bytes:
    """Decompresses raw 1C deflate stream when present, returning bytes as-is otherwise."""
    if not raw or raw.startswith(CONTAINER_MAGIC):
        return raw
    for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
        try:
            return zlib.decompress(raw, wbits)
        except Exception:
            pass
    return raw


def decode_text(raw: bytes) -> str:
    """Decodes UTF-8/UTF-16 1C stream and strips BOM and ASCII control bytes."""
    if not raw:
        return ""
    if raw.startswith(b"\xef\xbb\xbf"):
        text = raw[3:].decode("utf-8", errors="replace")
    elif raw.startswith(b"\xff\xfe"):
        text = raw.decode("utf-16-le", errors="replace").lstrip("\ufeff")
    elif raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16-be", errors="replace").lstrip("\ufeff")
    else:
        text = raw.decode("utf-8", errors="replace")
    return CONTROL_CHARS_RE.sub("", text)


def _is_dtools_blob(val: Any) -> bool:
    """Detects onec_dtools Blob wrapper without triggering lazy .value evaluation."""
    return type(val).__name__ == "Blob" or hasattr(type(val), "value")


def read_blob_bytes(blob: Any) -> bytes:
    """Reads bytes from a 1CD Blob object or raw bytes safely (handles onec_dtools StopIteration bug)."""
    if blob is None:
        return b""
    if isinstance(blob, (bytes, bytearray)):
        return bytes(blob)
    if _is_dtools_blob(blob):
        try:
            raw = blob.value
            if isinstance(raw, (bytes, bytearray)):
                return bytes(raw)
            if isinstance(raw, str):
                return raw.encode("utf-8", errors="replace")
            return bytes(raw)
        except (RuntimeError, StopIteration):
            return b""
    return bytes(blob)


def format_cell(val: Any, redact: bool = False, sanitize: bool = True) -> Any:
    """Formats a 1CD field value into JSON-safe printable representation."""
    if redact:
        return "<REDACTED>"
    if val is None:
        return None
    if isinstance(val, (bool, int, float)):
        return val
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if len(b) == 16:
            return b.hex()
        if len(b) <= 64:
            return f"0x{b.hex()}"
        return f"<bytes:{len(b)}>"
    if _is_dtools_blob(val):
        raw = read_blob_bytes(val)
        return f"<blob:{len(raw)} bytes>"
    s = str(val)
    return clean_text(s) if sanitize else s


def find_1c_executable() -> str | None:
    """Locates installed 1C:Enterprise executable (1cv8.exe / 1cv8t.exe / onec)."""
    for exe in ("1cv8t.exe", "1cv8.exe", "1cv8s.exe", "1cv8", "1cv8t"):
        found = shutil.which(exe)
        if found:
            return found

    roots = [
        r"C:\Program Files\1cv8",
        r"C:\Program Files (x86)\1cv8",
        r"C:\Program Files\1cv8t",
        r"C:\Program Files (x86)\1cv8t",
    ]
    candidates: list[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in ("1cv8.exe", "1cv8t.exe", "1cv8s.exe"):
                if name in filenames:
                    candidates.append(os.path.join(dirpath, name))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0]


def ensure_1cd_from_dt(dt_path: str, force: bool = False) -> str:
    """Converts a .dt dump into a cached 1Cv8.1CD database via CREATEINFOBASE /RestoreIB."""
    abs_dt = os.path.abspath(dt_path)
    st = os.stat(abs_dt)
    sig = f"{abs_dt}|{st.st_size}|{st.st_mtime_ns}".encode("utf-8")
    digest = hashlib.sha256(sig).hexdigest()[:16]
    cache_root = os.path.join(tempfile.gettempdir(), "onec_inspector_cache", digest)
    db_path = os.path.join(cache_root, "1Cv8.1CD")

    if not force and os.path.isfile(db_path):
        return db_path

    exe = find_1c_executable()
    if not exe:
        raise RuntimeError(
            "Для чтения .dt файла необходим установленный 1cv8.exe / 1cv8t.exe. "
            "Платформа 1С не найдена в системе."
        )

    if os.path.isdir(cache_root):
        shutil.rmtree(cache_root, ignore_errors=True)
    os.makedirs(cache_root, exist_ok=True)

    cmd = [
        exe,
        "CREATEINFOBASE",
        f"File={cache_root}",
        "/RestoreIB",
        abs_dt,
        "/DisableStartupDialogs",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0 or not os.path.isfile(db_path):
        raise RuntimeError(
            f"Не удалось распаковать .dt (code={proc.returncode}): {proc.stdout}\n{proc.stderr}"
        )
    return db_path


def parse_v8_tree(text: str) -> Any:
    """Parses 1C bracketed serialization '{a,"b",{c,d}}' into nested Python lists.

    Optimized iterative parser that handles escaped quotes '""' cleanly and never
    hits Python recursion limits on deep forms or metadata blobs.
    """
    n = len(text)
    i = 0
    # Skip leading whitespace / BOM
    while i < n and text[i] in " \t\r\n\ufeff":
        i += 1
    if i >= n or text[i] != "{":
        return None

    stack: list[list[Any]] = []
    root: list[Any] | None = None

    while i < n:
        ch = text[i]
        if ch in " \t\r\n,":
            i += 1
            continue
        if ch == "{":
            new_list: list[Any] = []
            if stack:
                stack[-1].append(new_list)
            else:
                root = new_list
            stack.append(new_list)
            i += 1
            continue
        if ch == "}":
            if stack:
                stack.pop()
                if not stack:
                    break
            i += 1
            continue
        if ch == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                c = text[i]
                if c == '"':
                    if i + 1 < n and text[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(c)
                i += 1
            if stack:
                stack[-1].append("".join(buf))
            continue
        # Unquoted token (number, UUID, #base64:..., etc.)
        start = i
        while i < n and text[i] not in ",{}\r\n":
            i += 1
        token = text[start:i].strip()
        if token and stack:
            stack[-1].append(token)

    return root


def pick_primary_table(db_entries: list[tuple[str, str]]) -> str | None:
    """Selects primary physical DB table among DBNames entries for a metadata object."""
    if not db_entries:
        return None
    priority = (
        "Reference",
        "Document",
        "AccumRg",
        "InfoRg",
        "Enum",
        "Const",
        "Chrc",
        "Acc",
        "CJ",
        "BPr",
        "Task",
    )
    for pref in priority:
        for kind, num in db_entries:
            if kind.lower() == pref.lower():
                return f"_{kind.upper()}{num}"
    kind, num = db_entries[0]
    return f"_{kind.upper()}{num}"


class ConfigSource:
    """Unified read interface for .dt, .1CD, .cf, .cfe, .epf, .ert, .efd, and unpacked dirs."""

    def __init__(self, path: str, config_table: str = "CONFIG", force_reload: bool = False):
        self.original_path = os.path.abspath(path)
        self.config_table = config_table.upper()
        self.force_reload = force_reload
        self.kind: str = ""
        self._file = None
        self.db = None
        self.container = None
        self._dir_root: str | None = None
        self._config_rows_cache: dict[str, bytes] | None = None
        self._container_entries_cache: list[str] | None = None
        self._db_names_cache: dict[str, list[tuple[str, str]]] | None = None
        self._db_names_raw_text: str | None = None

        # Single-pass .1CD row/stats cache to prevent iterator exhaustion in onec_dtools
        self._table_rows_cache: dict[str, list[dict[str, Any]]] = {}
        self._table_slots_cache: dict[str, int] = {}
        self._table_fields_cache: dict[str, list[str]] = {}
        self._all_tables_cached: bool = False
        self._ref_labels_cache: dict[str, str] | None = None

    def __enter__(self) -> "ConfigSource":
        ext = os.path.splitext(self.original_path)[1].lower()
        if os.path.isdir(self.original_path):
            if os.path.isfile(os.path.join(self.original_path, "root")):
                self.kind = "dir"
                self._dir_root = self.original_path
                return self
            cd_candidate = os.path.join(self.original_path, "1Cv8.1CD")
            if os.path.isfile(cd_candidate):
                self._open_1cd(cd_candidate)
                return self
            raise ValueError(
                f"Каталог '{self.original_path}' не содержит 'root' или '1Cv8.1CD'."
            )
        if ext == ".dt":
            db_path = ensure_1cd_from_dt(self.original_path, force=self.force_reload)
            self._open_1cd(db_path)
        elif ext == ".1cd":
            self._open_1cd(self.original_path)
        elif ext in CONTAINER_EXTS:
            self.kind = "container"
            self._file = open(self.original_path, "rb")
            self.container = onec_dtools.ContainerReader(self._file)
        else:
            raise ValueError(
                f"Неподдерживаемый тип источника '{ext}'. "
                "Ожидаются .dt, .1CD, .cf, .cfe, .epf, .ert, .efd или распакованный каталог."
            )
        return self

    def _open_1cd(self, db_path: str) -> None:
        self.kind = "1cd"
        self._file = open(db_path, "rb")
        self.db = onec_dtools.DatabaseReader(self._file)

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def _ensure_config_cache(self) -> None:
        if self._config_rows_cache is not None:
            return
        cache: dict[str, bytes] = {}
        tbl_name = self.config_table if self.config_table in self.db.tables else "CONFIG"
        for row in self.db.tables[tbl_name]:
            if not row.is_empty:
                cache[row["FILENAME"]] = read_blob_bytes(row["BINARYDATA"])
        self._config_rows_cache = cache

    def list_files(self) -> list[str]:
        if self.kind == "1cd":
            self._ensure_config_cache()
            return sorted(self._config_rows_cache.keys())
        if self.kind == "dir":
            assert self._dir_root is not None
            return sorted(
                fn for fn in os.listdir(self._dir_root)
                if os.path.isfile(os.path.join(self._dir_root, fn))
            )
        if self._container_entries_cache is None:
            self._container_entries_cache = sorted(self.container.entries.keys())
        return self._container_entries_cache

    def exists(self, name: str) -> bool:
        if self.kind == "1cd":
            self._ensure_config_cache()
            return name in self._config_rows_cache
        if self.kind == "dir":
            assert self._dir_root is not None
            return os.path.isfile(os.path.join(self._dir_root, name))
        return name in self.container.entries

    def read_bytes(self, name: str, raw: bool = False) -> bytes | None:
        if self.kind == "1cd":
            self._ensure_config_cache()
            data = self._config_rows_cache.get(name)
            if data is None:
                return None
            return data if raw else decompress_1c(data)
        if self.kind == "dir":
            assert self._dir_root is not None
            fpath = os.path.join(self._dir_root, name)
            if not os.path.isfile(fpath):
                return None
            with open(fpath, "rb") as fh:
                data = fh.read()
            return data if raw else decompress_1c(data)
        entry = self.container.entries.get(name)
        if entry is None:
            return None
        data = b"".join(entry.data)
        return data if raw else decompress_1c(data)

    def read_text(self, name: str) -> str | None:
        data = self.read_bytes(name)
        if data is None or data.startswith(CONTAINER_MAGIC):
            return None
        return decode_text(data)

    def read_container_subfile(self, fname: str, entry_names: tuple[str, ...] = ("text", "module")) -> str | None:
        """If fname is a packed 1C container, unpacks preferred sub-entry text."""
        data = self.read_bytes(fname)
        if not data or not data.startswith(CONTAINER_MAGIC):
            return None
        cr = onec_dtools.ContainerReader(io.BytesIO(data))
        for ename in entry_names:
            if ename in cr.entries:
                return decode_text(decompress_1c(b"".join(cr.entries[ename].data)))
        return None

    def read_db_names_raw(self) -> str:
        """Reads decompressed PARAMS/DBNames text on 1CD databases."""
        if self._db_names_raw_text is not None:
            return self._db_names_raw_text
        if self.kind != "1cd":
            self._db_names_raw_text = ""
            return ""
        for row in self.get_table_rows("PARAMS"):
            if row.get("FILENAME") == "DBNames":
                raw_blob = row.get("BINARYDATA")
                # BINARYDATA may be raw bytes or Blob from cached row
                raw = read_blob_bytes(raw_blob)
                self._db_names_raw_text = decode_text(decompress_1c(raw))
                return self._db_names_raw_text
        self._db_names_raw_text = ""
        return ""

    def get_db_names(self) -> dict[str, list[tuple[str, str]]]:
        """Returns {uuid: [(table_kind, id_num), ...]} from PARAMS/DBNames on 1CD bases."""
        if self._db_names_cache is not None:
            return self._db_names_cache
        mapping: dict[str, list[tuple[str, str]]] = {}
        if self.kind != "1cd":
            self._db_names_cache = mapping
            return mapping
        txt = self.read_db_names_raw()
        if txt:
            for uid, kind, num in re.findall(
                r"\{([0-9a-f-]{36}),\"([A-Za-z]+)\",(\d+)\}", txt, re.I
            ):
                mapping.setdefault(uid.lower(), []).append((kind, num))
        self._db_names_cache = mapping
        return mapping

    def _read_table_once(self, table_name: str) -> None:
        """Reads and caches a .1CD table in a single pass, redacting V8USERS.DATA."""
        if self.kind != "1cd" or table_name in self._table_rows_cache:
            return
        if table_name not in self.db.tables:
            return
        tbl = self.db.tables[table_name]
        fields = list(tbl.fields.keys())
        self._table_fields_cache[table_name] = fields
        self._table_slots_cache[table_name] = len(tbl)
        rows_out: list[dict[str, Any]] = []
        is_users = table_name.upper() == "V8USERS"
        for r in tbl:
            if r.is_empty:
                continue
            rec: dict[str, Any] = {}
            for col in fields:
                if is_users and col.upper() == "DATA":
                    rec[col] = "<REDACTED>"
                else:
                    val = r[col]
                    # Materialize blobs immediately while row cursor is valid
                    if _is_dtools_blob(val):
                        rec[col] = read_blob_bytes(val)
                    else:
                        rec[col] = val
            rows_out.append(rec)
        self._table_rows_cache[table_name] = rows_out

    def get_table_fields(self, table_name: str) -> list[str]:
        if self.kind != "1cd" or table_name not in self.db.tables:
            return []
        if table_name not in self._table_fields_cache:
            self._table_fields_cache[table_name] = list(self.db.tables[table_name].fields.keys())
        return self._table_fields_cache[table_name]

    def get_table_rows(self, table_name: str) -> list[dict[str, Any]]:
        if self.kind != "1cd":
            return []
        self._read_table_once(table_name)
        return self._table_rows_cache.get(table_name, [])

    def get_table_slots(self, table_name: str) -> int:
        if self.kind != "1cd" or table_name not in self.db.tables:
            return 0
        if table_name not in self._table_slots_cache:
            self._table_slots_cache[table_name] = len(self.db.tables[table_name])
        return self._table_slots_cache[table_name]

    def get_all_table_stats(self) -> dict[str, dict[str, Any]]:
        """Reads every table once and returns exact non-empty counts + slot counts."""
        if self.kind != "1cd":
            return {}
        if not self._all_tables_cached:
            for tname in sorted(self.db.tables.keys()):
                self._read_table_once(tname)
            self._all_tables_cached = True
        return {
            tname: {
                "non_empty": len(self._table_rows_cache.get(tname, [])),
                "slots": self._table_slots_cache.get(tname, 0),
                "fields": self._table_fields_cache.get(tname, []),
            }
            for tname in sorted(self.db.tables.keys())
        }

    def build_ref_labels(self, table_to_label: dict[str, str] | None = None) -> dict[str, str]:
        """Builds {32-hex-IDRREF: human-readable label} across all cached .1CD tables."""
        if self._ref_labels_cache is not None:
            return self._ref_labels_cache
        labels: dict[str, str] = {"00000000000000000000000000000000": "<Пусто>"}
        if self.kind != "1cd":
            self._ref_labels_cache = labels
            return labels
        stats = self.get_all_table_stats()
        for tname, info in stats.items():
            fnames = set(info["fields"])
            if "_IDRREF" not in fnames:
                continue
            base = (table_to_label or {}).get(tname, tname)
            for row in self.get_table_rows(tname):
                rid = format_cell(row.get("_IDRREF"))
                if not isinstance(rid, str):
                    continue
                if "_DESCRIPTION" in fnames:
                    desc = clean_text(row.get("_DESCRIPTION") or "").strip()
                    labels[rid] = f"{base}: {desc}"
                elif "_NUMBER" in fnames:
                    num = clean_text(row.get("_NUMBER") or "").strip()
                    dt = clean_text(row.get("_DATE_TIME") or "")[:10]
                    labels[rid] = f"{base} №{num} ({dt})" if dt else f"{base} №{num}"
                elif "_ENUMORDER" in fnames:
                    labels[rid] = f"{base}[#{row.get('_ENUMORDER')}]"
        self._ref_labels_cache = labels
        return labels

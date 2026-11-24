"""Zero-dependency pure-Python MCP (stdio JSON-RPC 2.0) server for onec-inspector."""

from __future__ import annotations

import io
import json
import os
import re
import sys
from typing import Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import onec_dtools  # noqa: E402

from onec_audit import run_audit  # noqa: E402
from onec_core import (  # noqa: E402
    CONTAINER_MAGIC,
    ConfigSource,
    clean_text,
    decode_text,
    decompress_1c,
    format_cell,
)
from onec_meta import (  # noqa: E402
    build_file_owner_map,
    build_type_uuid_map,
    collect_all_modules,
    collect_object_modules,
    extract_config_properties,
    find_matching_objects,
    find_xrefs,
    load_metadata_index,
    load_subsystems_tree,
    parse_dcs_schemas,
    parse_forms,
    parse_object_details,
    parse_roles,
    read_bsl_from_file,
    read_users_safe,
    resolve_table_mappings,
)

SERVER_INFO = {"name": "onec-inspector", "version": "2.0.0"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "onec_summary",
        "description": "Обзор конфигурации 1С (.dt, .1CD, .cf, .cfe, .epf, .ert, .efd или распакованный каталог): свойства конфигурации, классы метаданных, список объектов и корневые модули.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Путь к файлу 1С или распакованному каталогу"},
                "table": {"type": "string", "default": "CONFIG", "description": "CONFIG или CONFIGSAVE (для .1CD)"},
                "include_images": {"type": "boolean", "default": False, "description": "Включать ли список общих картинок"},
                "force_reload": {"type": "boolean", "default": False},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_subsystems",
        "description": "Рекурсивное дерево подсистем конфигурации 1С (включая вложенные подсистемы) и список бизнес-объектов вне подсистем.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_object",
        "description": "Детальная информация об объекте метаданных 1С: реквизиты и их типы, табличные части, измерения/ресурсы регистров, значения перечислений, движения документов, физические таблицы .1CD и формы/команды.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string", "description": "Имя, Класс.Имя или UUID объекта"},
                "class_filter": {"type": "string", "description": "Необязательный фильтр по классу метаданных"},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path", "query"],
        },
    },
    {
        "name": "onec_modules",
        "description": "Извлечение BSL-кода модулей конфигурации/объекта/форм или получение списка всех модулей конфигурации.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string", "description": "Имя/UUID объекта или 'Конфигурация'; опустите при list_only=true"},
                "list_only": {"type": "boolean", "default": False, "description": "Вернуть только оглавление модулей без исходного кода"},
                "all_modules": {"type": "boolean", "default": False, "description": "Извлечь код всех модулей (осторожно на больших базах)"},
                "class_filter": {"type": "string"},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_dcs",
        "description": "Разбор схем компоновки данных (СКД / DataCompositionSchema) отчетов и обработок: запросы, наборы данных, параметры, вычисляемые поля, ресурсы.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string", "description": "Имя отчета/обработки; опустите для всех отчетов и обработок"},
                "include_xml": {"type": "boolean", "default": False},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_forms",
        "description": "Инспекция управляемых и обычных форм: процедуры модуля, привязки событий и отсутствующие обработчики событий.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string", "description": "Имя владельца/формы; опустите для всех форм"},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_roles",
        "description": "Разбор ролей конфигурации 1С: права по объектам метаданных (+1/-1) и поиск побайтно-идентичных дублей ролей.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "details": {"type": "boolean", "default": True, "description": "Включать детальный список объектов по каждой роли"},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_users",
        "description": "Безопасное чтение таблицы V8USERS из .1CD/.dt (поле DATA/хэши паролей строго редактируются).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "onec_search",
        "description": "Поиск строки в метаданных и/или BSL-модулях конфигурации 1С.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string"},
                "modules_only": {"type": "boolean", "default": False},
                "ignore_case": {"type": "boolean", "default": False},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path", "query"],
        },
    },
    {
        "name": "onec_xref",
        "description": "Поиск всех ссылок на объект/UUID в конфигурации или поиск неиспользуемых объектов (unused_only=true).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string", "description": "Имя или UUID объекта"},
                "unused_only": {"type": "boolean", "default": False},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_tables",
        "description": "Список физических таблиц .1CD/.dt с точным количеством непустых записей, числом слотов и привязкой к DBNames.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "non_empty_only": {"type": "boolean", "default": False},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_rows",
        "description": "Чтение записей таблицы .1CD/.dt по физическому имени, имени объекта или Объект.ТабличнаяЧасть с расшифровкой колонок _FLD и GUID-ссылок.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "table_name": {"type": "string", "description": "Например: _DOCUMENT334_VT345, Номенклатура или ПоступлениеТоваров.Номенклатура"},
                "limit": {"type": "integer", "default": 20},
                "resolve_refs": {"type": "boolean", "default": True},
                "where": {"type": "string", "description": "Необязательный фильтр по подстроке"},
                "class_filter": {"type": "string"},
            },
            "required": ["path", "table_name"],
        },
    },
    {
        "name": "onec_audit",
        "description": "Комплексная универсальная диагностика конфигурации 1С: неиспользуемые объекты, битые ссылки BSL на перечисления/метаданные, модальные вызовы, запросы в циклах, пустые Исключение, расхождение движений, битые обработчики форм, потеря точности чисел между документами и регистрами, дубли ролей, аудит V8USERS и целостность данных ИБ.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "include_data": {"type": "boolean", "default": True},
                "table": {"type": "string", "default": "CONFIG"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "onec_raw",
        "description": "Чтение сырого внутреннего файла конфигурации (root, DBNames или UUID) с распаковкой deflate/вложенных контейнеров.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "filename": {"type": "string"},
                "table": {"type": "string", "default": "CONFIG"},
                "max_chars": {"type": "integer", "default": 20000},
            },
            "required": ["path", "filename"],
        },
    },
]


def handle_tool_call(name: str, args: dict[str, Any]) -> Any:
    path = args["path"]
    table = args.get("table", "CONFIG")
    force_reload = bool(args.get("force_reload", False))

    if name == "onec_summary":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            props = extract_config_properties(src, cfg)
            include_img = bool(args.get("include_images", False))
            grouped: dict[str, list[dict[str, str]]] = {}
            for it in items:
                grouped.setdefault(it["class_name"], []).append(it)
            filtered_items = (
                items if include_img else [i for i in items if i["class_name"] != "Общие картинки"]
            )
            return {
                "source_kind": src.kind,
                "config": props,
                "counts": {k: len(v) for k, v in grouped.items()},
                "objects": filtered_items,
            }

    if name == "onec_subsystems":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            return {"config": cfg, **load_subsystems_tree(src, items)}

    if name == "onec_object":
        with ConfigSource(path, table, force_reload) as src:
            _, items = load_metadata_index(src)
            matches = find_matching_objects(items, args["query"], class_filter=args.get("class_filter"))
            if not matches:
                raise ValueError(f"Объект '{args['query']}' не найден.")
            type_map = build_type_uuid_map(src, items)
            res = [parse_object_details(src, m, type_map) for m in matches]
            return res[0] if len(res) == 1 else res

    if name == "onec_modules":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            list_only = bool(args.get("list_only", False))
            all_mods = bool(args.get("all_modules", False))
            query = args.get("query")
            cls_f = args.get("class_filter")
            if all_mods or list_only or not query:
                mods = collect_all_modules(src, cfg, items, class_filter=cls_f)
            elif query.lower() in (cfg["uuid"], (cfg["name"] or "").lower(), "конфигурация"):
                mods = collect_object_modules(src, cfg["uuid"], cfg["name"] or "Конфигурация", "Конфигурация")
            else:
                matches = find_matching_objects(items, query, class_filter=cls_f)
                if not matches and src.exists(query):
                    code = read_bsl_from_file(src, query)
                    mods = (
                        [{"title": query, "filename": query, "owner_name": query, "owner_class": "", "owner_uuid": query, "module_kind": "Файл", "code": code, "lines": len(code.splitlines())}]
                        if code else []
                    )
                elif not matches:
                    raise ValueError(f"Объект или файл '{query}' не найден.")
                else:
                    mods = []
                    for m in matches:
                        mods.extend(collect_object_modules(src, m["uuid"], m["name"], m["class_name"]))
            if list_only:
                return [{k: v for k, v in m.items() if k != "code"} for m in mods]
            return mods

    if name == "onec_dcs":
        with ConfigSource(path, table, force_reload) as src:
            _, items = load_metadata_index(src)
            schemas = parse_dcs_schemas(src, items, args.get("query"))
            if not args.get("include_xml", False):
                schemas = [{k: v for k, v in s.items() if k != "xml"} for s in schemas]
            return schemas

    if name == "onec_forms":
        with ConfigSource(path, table, force_reload) as src:
            _, items = load_metadata_index(src)
            return parse_forms(src, items, args.get("query"))

    if name == "onec_roles":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            res = parse_roles(src, cfg, items)
            if not args.get("details", True):
                for r in res["roles"]:
                    r.pop("objects", None)
            return res

    if name == "onec_users":
        with ConfigSource(path, "CONFIG", force_reload) as src:
            return read_users_safe(src)

    if name == "onec_search":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            owners = build_file_owner_map(src, cfg, items)
            flags = re.IGNORECASE if args.get("ignore_case") else 0
            pat = re.compile(re.escape(args["query"]), flags)
            image_uuids = {i["uuid"] for i in items if i["class_name"] == "Общие картинки"}
            modules_only = bool(args.get("modules_only", False))
            hits = []
            for fn in src.list_files():
                base = fn.split(".")[0].lower()
                if base in image_uuids:
                    continue
                code = read_bsl_from_file(src, fn)
                text = code if modules_only else (code or src.read_text(fn))
                if text and pat.search(text):
                    label = owners.get(base, fn)
                    lines = [
                        {"line": ln, "text": clean_text(line.strip())[:200]}
                        for ln, line in enumerate(text.splitlines(), 1)
                        if pat.search(line)
                    ]
                    hits.append({"file": fn, "owner": label, "matches": lines[:20]})
            return hits

    if name == "onec_xref":
        with ConfigSource(path, table, force_reload) as src:
            cfg, items = load_metadata_index(src)
            unused_only = bool(args.get("unused_only", False)) or not args.get("query")
            return find_xrefs(src, cfg, items, target_query=args.get("query"), unused_only=unused_only)

    if name == "onec_tables":
        with ConfigSource(path, "CONFIG", force_reload) as src:
            if src.kind != "1cd":
                raise ValueError("onec_tables поддерживается только для .1CD и .dt.")
            _, items = load_metadata_index(src)
            mappings = resolve_table_mappings(src, items)
            stats = src.get_all_table_stats()
            non_empty_only = bool(args.get("non_empty_only", False))
            out = []
            for tname, info in stats.items():
                if non_empty_only and info["non_empty"] == 0:
                    continue
                out.append(
                    {
                        "table": tname,
                        "non_empty": info["non_empty"],
                        "slots": info["slots"],
                        "metadata": mappings["table_to_label"].get(tname, ""),
                        "fields": info["fields"],
                    }
                )
            return {"version": src.db.version, "locale": src.db.locale, "tables": out}

    if name == "onec_rows":
        with ConfigSource(path, "CONFIG", force_reload) as src:
            if src.kind != "1cd":
                raise ValueError("onec_rows поддерживается только для .1CD и .dt.")
            _, items = load_metadata_index(src)
            mappings = resolve_table_mappings(src, items)
            tmap_col = mappings["table_to_colmap"]
            tmap_lbl = mappings["table_to_label"]
            lkp = mappings["lookup_index"]

            q = args["table_name"].strip()
            table_name = None
            col_map: dict[str, str] = {}
            label = q
            if q in src.db.tables:
                table_name = q
                col_map = tmap_col.get(table_name, {})
                label = tmap_lbl.get(table_name, table_name)
            elif q.lower() in lkp:
                table_name, col_map, label = lkp[q.lower()]
            else:
                matches = find_matching_objects(items, q, class_filter=args.get("class_filter"))
                if matches:
                    det = parse_object_details(src, matches[0])
                    if det["physical_table"] in src.db.tables:
                        table_name = det["physical_table"]
                        col_map = tmap_col.get(table_name, {})
                        label = tmap_lbl.get(table_name, matches[0]["name"])
            if not table_name or table_name not in src.db.tables:
                raise ValueError(f"Таблица '{args['table_name']}' не найдена в 1CD.")

            rows = src.get_table_rows(table_name)
            slots = src.get_table_slots(table_name)
            fields = src.get_table_fields(table_name)
            resolve_refs = bool(args.get("resolve_refs", True))
            ref_labels = src.build_ref_labels(tmap_lbl) if resolve_refs else {}
            where_q = args["where"].lower() if args.get("where") else None
            limit = int(args.get("limit", 20))

            out_rows = []
            for r in rows:
                rec = {}
                for col in fields:
                    dcol = col_map.get(col, col)
                    redact = table_name.upper() == "V8USERS" and col.upper() == "DATA"
                    val = format_cell(r.get(col), redact=redact)
                    if (
                        resolve_refs
                        and isinstance(val, str)
                        and val in ref_labels
                        and (col.endswith("RREF") or col == "_IDRREF")
                    ):
                        val = f"{val} ({ref_labels[val]})"
                    rec[dcol] = val
                if where_q and where_q not in json.dumps(rec, ensure_ascii=False).lower():
                    continue
                out_rows.append(rec)
                if limit > 0 and len(out_rows) >= limit:
                    break
            return {
                "table": table_name,
                "label": label,
                "non_empty_total": len(rows),
                "slots": slots,
                "returned": len(out_rows),
                "rows": out_rows,
            }

    if name == "onec_audit":
        with ConfigSource(path, table, force_reload) as src:
            return run_audit(src, include_data=bool(args.get("include_data", True)))

    if name == "onec_raw":
        with ConfigSource(path, table, force_reload) as src:
            fn = args["filename"]
            max_chars = int(args.get("max_chars", 20000))
            if fn.upper() == "DBNAMES" and src.kind == "1cd":
                return src.read_db_names_raw()[:max_chars]
            data = src.read_bytes(fn)
            if data is None:
                raise ValueError(f"Файл '{fn}' не найден.")
            if data.startswith(CONTAINER_MAGIC):
                cr = onec_dtools.ContainerReader(io.BytesIO(data))
                parts = []
                for ek, eobj in cr.entries.items():
                    ed = decode_text(decompress_1c(b"".join(eobj.data)))
                    parts.append(f"--- {ek} ---\n{ed}")
                return "\n".join(parts)[:max_chars]
            return decode_text(data)[:max_chars]

    raise ValueError(f"Неизвестный инструмент MCP: {name}")


def _send_message(msg: dict[str, Any], use_lsp_framing: bool) -> None:
    body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    if use_lsp_framing:
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        sys.stdout.buffer.write(header + body)
    else:
        sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


def _read_message() -> tuple[dict[str, Any] | None, bool]:
    """Reads either newline-delimited JSON-RPC or Content-Length framed JSON-RPC."""
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None, False
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hline = sys.stdin.buffer.readline()
                if not hline or hline in (b"\r\n", b"\n"):
                    break
            payload = sys.stdin.buffer.read(length)
            return json.loads(payload.decode("utf-8")), True
        return json.loads(stripped.decode("utf-8")), False


def main() -> None:
    while True:
        msg, framed = _read_message()
        if msg is None:
            break
        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        # Notifications have no id and expect no reply
        if req_id is None:
            continue

        try:
            if method == "initialize":
                proto = params.get("protocolVersion", "2024-11-05")
                result = {
                    "protocolVersion": proto,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                tname = params.get("name", "")
                targs = params.get("arguments") or {}
                try:
                    data = handle_tool_call(tname, targs)
                    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=2)
                    result = {"content": [{"type": "text", "text": text}], "isError": False}
                except Exception as exc:
                    result = {"content": [{"type": "text", "text": f"ERROR: {exc}"}], "isError": True}
            else:
                _send_message(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method not found: {method}"},
                    },
                    framed,
                )
                continue

            _send_message({"jsonrpc": "2.0", "id": req_id, "result": result}, framed)
        except Exception as exc:
            _send_message(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(exc)},
                },
                framed,
            )


if __name__ == "__main__":
    main()

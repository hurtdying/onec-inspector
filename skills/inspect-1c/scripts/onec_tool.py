"""Universal CLI tool for inspecting, searching, auditing, and unpacking 1C:Enterprise 8 files.

Supports .dt, .1CD, .cf, .cfe, .epf, .ert, .efd, and unpacked container directories.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys

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


def _dump_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def cmd_summary(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)
        props = extract_config_properties(src, cfg)
        sub_info = load_subsystems_tree(src, items) if getattr(args, "subsystems", False) else None

        grouped: dict[str, list[dict[str, str]]] = {}
        for item in items:
            grouped.setdefault(item["class_name"], []).append(item)

        if args.json:
            payload: dict[str, object] = {
                "source_kind": src.kind,
                "config": props,
                "counts": {k: len(v) for k, v in grouped.items()},
                "objects": items,
            }
            if sub_info is not None:
                payload["subsystems"] = sub_info
            _dump_json(payload)
            return

        print(f"Источник ({src.kind}): {args.path}")
        print(f"Конфигурация: {cfg['name']} («{cfg['synonym']}») [{cfg['uuid']}]")
        if props.get("comment"):
            print(f"Описание: {props['comment']}")
        if props.get("root_modules"):
            mods_s = ", ".join(f"{m['title']} ({m['lines']} стр.)" for m in props["root_modules"])
            print(f"Модули конфигурации: {mods_s}")

        for cname, lst in grouped.items():
            if cname == "Общие картинки" and len(lst) > 30:
                print(f"\n[{cname}] ({len(lst)}) — список скрыт (картинки); используйте --json при необходимости")
                continue
            print(f"\n[{cname}] ({len(lst)}):")
            for obj in lst:
                syn = f" — «{obj['synonym']}»" if obj["synonym"] and obj["synonym"] != obj["name"] else ""
                print(f"  - {obj['name']}{syn} [{obj['uuid']}]")

        if sub_info is not None:
            print("\n=== Дерево подсистем ===")
            _print_subsystems_tree(sub_info)


def _print_subsystems_tree(sub_info: dict, indent: int = 0) -> None:
    def _walk(nodes: list[dict], depth: int) -> None:
        pad = "  " * depth
        for node in nodes:
            syn = f" («{node['synonym']}»)" if node["synonym"] and node["synonym"] != node["name"] else ""
            print(f"{pad}- {node['name']}{syn} [{node['uuid']}] — объектов: {len(node['objects'])}")
            for obj in node["objects"]:
                print(f"{pad}    • [{obj['class_name']}] {obj['name']}")
            if node["children"]:
                _walk(node["children"], depth + 1)

    _walk(sub_info["subsystems"], indent)
    unassigned = sub_info["unassigned_business_objects"]
    if unassigned:
        print(f"\nОбъекты вне подсистем ({len(unassigned)}):")
        for u in unassigned:
            print(f"  - [{u['class_name']}] {u['name']} [{u['uuid']}]")


def cmd_subsystems(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)
        sub_info = load_subsystems_tree(src, items)
        if args.json:
            _dump_json({"config": cfg, **sub_info})
            return
        print(f"Конфигурация: {cfg['name']} — подсистем верхнего уровня: {len(sub_info['subsystems'])}")
        _print_subsystems_tree(sub_info)


def cmd_object(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        _, items = load_metadata_index(src)
        matches = find_matching_objects(items, args.query, class_filter=args.obj_class)
        if not matches:
            print(f"Объект '{args.query}' не найден.", file=sys.stderr)
            sys.exit(1)

        type_map = build_type_uuid_map(src, items)
        results = [parse_object_details(src, m, type_map) for m in matches]
        if args.json:
            _dump_json(results[0] if len(results) == 1 else results)
            return

        for idx, res in enumerate(results):
            if idx:
                print("\n" + "=" * 60)
            obj = res["object"]
            print(f"Объект: {obj['class_name']}.{obj['name']} («{obj['synonym']}»)")
            print(f"UUID: {obj['uuid']}")
            if res.get("description"):
                print(f"Описание: {res['description']}")
            if res["physical_table"]:
                print(f"Таблица 1CD: {res['physical_table']} (все: {', '.join(res['physical_tables'])})")
            if res.get("properties"):
                print(f"Свойства: {res['properties']}")

            if res["register_records"]:
                print("Движения по регистрам:")
                for rr in res["register_records"]:
                    print(f"  - {rr['label']} [{rr['uuid']}]")

            if res.get("based_on"):
                print("Ввод на основании:")
                for bo in res["based_on"]:
                    print(f"  - {bo['label']} [{bo['uuid']}]")

            if res["enum_values"]:
                print(f"Значения перечисления ({len(res['enum_values'])}):")
                for ev in res["enum_values"]:
                    syn = f" («{ev['synonym']}»)" if ev["synonym"] else ""
                    print(f"  - {ev['name']}{syn}")

            top_attrs = [a for a in res["attributes"] if not a["parent_ts"]]
            if top_attrs:
                print(f"Реквизиты / Измерения / Ресурсы ({len(top_attrs)}):")
                for attr in top_attrs:
                    t = f" : {attr['type']}" if attr["type"] else ""
                    col = f" -> {attr['physical_col']}" if attr["physical_col"] else ""
                    print(f"  - [{attr['kind']}] {attr['name']}{t}{col}")

            if res["tabular_sections"]:
                print(f"Табличные части ({len(res['tabular_sections'])}):")
                for ts in res["tabular_sections"]:
                    vtn = f" -> {ts['physical_table']}" if ts["physical_table"] else ""
                    print(f"  - {ts['name']}{vtn} ({len(ts['columns'])} кол.)")
                    for col in ts["columns"]:
                        ct = f" : {col['type']}" if col["type"] else ""
                        ccol = f" -> {col['physical_col']}" if col["physical_col"] else ""
                        print(f"      • {col['name']}{ct}{ccol}")

            if res["child_objects"]:
                print(f"Формы / Команды / Макеты ({len(res['child_objects'])}):")
                for ch in res["child_objects"]:
                    print(f"  - [{ch['kind']}] {ch['name']} («{ch['synonym']}») [{ch['uuid']}]")


def cmd_module(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)

        if args.all or args.list or not args.query:
            modules = collect_all_modules(src, cfg, items, class_filter=args.obj_class)
        else:
            if args.query.lower() in (cfg["uuid"], (cfg["name"] or "").lower(), "конфигурация"):
                modules = collect_object_modules(src, cfg["uuid"], cfg["name"] or "Конфигурация", "Конфигурация")
            else:
                matches = find_matching_objects(items, args.query, class_filter=args.obj_class)
                if not matches:
                    if src.exists(args.query):
                        code = read_bsl_from_file(src, args.query)
                        modules = (
                            [
                                {
                                    "title": args.query,
                                    "filename": args.query,
                                    "owner_name": args.query,
                                    "owner_class": "",
                                    "owner_uuid": args.query,
                                    "module_kind": "Файл",
                                    "code": code,
                                    "lines": len(code.splitlines()),
                                }
                            ]
                            if code
                            else []
                        )
                    else:
                        print(f"Объект или файл '{args.query}' не найден.", file=sys.stderr)
                        sys.exit(1)
                else:
                    modules = []
                    for m in matches:
                        modules.extend(collect_object_modules(src, m["uuid"], m["name"], m["class_name"]))

        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            if os.path.isdir(args.out) or (not args.out.endswith(".txt") and not args.out.endswith(".bsl") and args.all):
                os.makedirs(args.out, exist_ok=True)
                for idx, m in enumerate(modules, 1):
                    safe_name = re.sub(r'[<>:"/\\|?*]+', "_", f"{idx:03d}_{m['owner_name']}_{m['filename']}.bsl")
                    with open(os.path.join(args.out, safe_name), "w", encoding="utf-8") as fh:
                        fh.write(f"// {m['title']}\n{m['code']}")
                print(f"Выгружено модулей: {len(modules)} -> {args.out}")
                return
            with open(args.out, "w", encoding="utf-8") as fh:
                for m in modules:
                    fh.write(f"// {'=' * 60}\n// {m['title']} ({m['lines']} стр.)\n// {'=' * 60}\n{m['code']}\n\n")
            print(f"Выгружено модулей: {len(modules)} -> {args.out}")
            return

        if args.json:
            payload = (
                [
                    {k: v for k, v in m.items() if k != "code"}
                    for m in modules
                ]
                if args.list
                else modules
            )
            _dump_json(payload)
            return

        if args.list:
            print(f"Всего модулей: {len(modules)}")
            for m in modules:
                print(f"  {m['filename']:44} | {m['lines']:4d} стр. | {m['owner_class']}.{m['owner_name']} ({m['module_kind']})")
            return

        if not modules:
            print("BSL-модули не найдены.")
            return

        for m in modules:
            print(f"\n// {'=' * 60}")
            print(f"// {m['title']} ({m['lines']} стр.)")
            print(f"// {'=' * 60}")
            print(m["code"])


def cmd_dcs(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        _, items = load_metadata_index(src)
        target = None if args.all else args.query
        schemas = parse_dcs_schemas(src, items, target)
        if args.json:
            out = schemas if args.xml else [{k: v for k, v in s.items() if k != "xml"} for s in schemas]
            _dump_json(out)
            return
        if not schemas:
            print("Схемы компоновки данных (СКД) не найдены.")
            return
        for s in schemas:
            print(f"\n=== [{s['object_class']}] {s['object_name']} / {s['template_name']} ({s['file']}) ===")
            if s.get("parse_error"):
                print(f"  WARN XML parse: {s['parse_error']}")
            for ds in s["datasets"]:
                print(f"  Набор данных: {ds['name']} (полей: {len(ds['fields'])})")
                if ds["fields"]:
                    print(f"    Поля: {', '.join(ds['fields'])}")
                if ds["query"]:
                    print("    Запрос СКД:")
                    for line in ds["query"].splitlines():
                        print(f"      {line}")
            if s["calculated_fields"]:
                print("  Вычисляемые поля:")
                for cf in s["calculated_fields"]:
                    print(f"    - {cf['data_path']} = {cf['expression']}")
            if s["total_fields"]:
                print("  Ресурсы:")
                for tf in s["total_fields"]:
                    print(f"    - {tf['data_path']} = {tf['expression']}")
            if s["parameters"]:
                print("  Параметры:", ", ".join(p["name"] for p in s["parameters"] if p["name"]))
            if s["selection_fields"]:
                print("  Поля настроек:", ", ".join(s["selection_fields"]))
            if args.xml:
                print("\n--- XML ---")
                print(s["xml"])


def cmd_forms(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        _, items = load_metadata_index(src)
        target = None if args.all else args.query
        forms = parse_forms(src, items, target)
        if args.json:
            _dump_json(forms)
            return
        if not forms:
            print("Формы не найдены.")
            return
        for f in forms:
            syn = f" («{f['form_synonym']}»)" if f["form_synonym"] else ""
            print(
                f"\n[{f['form_kind']}] {f['owner_class']}.{f['owner_name']}.{f['form_name']}{syn} "
                f"[{f['file']}] ({f['module_lines']} стр.)"
            )
            if f["procedures"]:
                print(f"  Процедуры/функции: {', '.join(f['procedures'])}")
            if f["bound_handlers"]:
                binds = ", ".join(f"{b['event']}->{b['handler']}" for b in f["bound_handlers"])
                print(f"  Привязки событий: {binds}")
            if f["missing_handlers"]:
                for mh in f["missing_handlers"]:
                    print(f"  ! ОШИБКА ПРИВЯЗКИ: {mh['event']} -> отсутствует процедура '{mh['handler']}'")


def cmd_roles(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)
        res = parse_roles(src, cfg, items)
        if args.json:
            _dump_json(res)
            return
        if res["duplicate_groups"]:
            print("Обнаружены побайтно идентичные роли:")
            for grp in res["duplicate_groups"]:
                print(f"  = {', '.join(grp)}")
        for r in res["roles"]:
            syn = f" («{r['synonym']}»)" if r["synonym"] else ""
            new_flag = " | ПраваНаНовыеОбъекты=Да (Полные права)" if r.get("set_rights_for_new_objects") else ""
            print(f"\nРоль: {r['name']}{syn} [{r['uuid']}] — объектов в правах: {r['objects_count']}{new_flag}")
            if args.details:
                for obj in r["objects"]:
                    print(f"    • {obj['object']}: +1={obj['granted']}, -1={obj['denied']} (записей={obj['total_entries']})")


def cmd_users(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, force_reload=args.force_reload) as src:
        res = read_users_safe(src)
        if args.json:
            _dump_json(res)
            return
        if not res["supported"]:
            print(res["reason"])
            sys.exit(1)
        print(f"Пользователи ИБ (V8USERS): {res['count']} (поле DATA редактировано/скрыто)")
        for u in res["users"]:
            print("  " + json.dumps(u, ensure_ascii=False))


def cmd_search(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)
        owners = build_file_owner_map(src, cfg, items)
        flags = re.IGNORECASE if args.ignore_case else 0
        pat = re.compile(re.escape(args.query), flags)
        image_uuids = {i["uuid"] for i in items if i["class_name"] == "Общие картинки"}

        hits = []
        for fn in src.list_files():
            base_uid = fn.split(".")[0].lower()
            if base_uid in image_uuids:
                continue
            code = read_bsl_from_file(src, fn)
            text = code if args.modules_only else (code or src.read_text(fn))
            if not text:
                continue
            if pat.search(text):
                label = owners.get(base_uid, fn)
                lines = [
                    (ln, clean_text(line.strip()))
                    for ln, line in enumerate(text.splitlines(), 1)
                    if pat.search(line)
                ]
                hits.append({"file": fn, "owner": label, "matches": lines[:20]})

        if args.json:
            _dump_json(hits)
            return

        print(f"Найдено совпадений по '{args.query}': {len(hits)}")
        for h in hits:
            print(f"\n[{h['file']}] ({h['owner']})")
            for ln, line in h["matches"][:8]:
                print(f"  L{ln}: {line[:160]}")


def cmd_xref(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        cfg, items = load_metadata_index(src)
        res = find_xrefs(src, cfg, items, target_query=args.query, unused_only=args.unused or not args.query)
        if args.json:
            _dump_json(res)
            return
        if res["mode"] == "unused":
            print(f"Просканировано файлов конфигурации: {res['scanned_files']}")
            print(f"Объекты без внешних ссылок ({len(res['unused_objects'])}):")
            for uo in res["unused_objects"]:
                print(f"  - [{uo['class_name']}] {uo['name']} [{uo['uuid']}]")
        elif res["mode"] == "object":
            t = res["target"]
            print(f"Ссылки на [{t['class_name']}] {t['name']} [{t['uuid']}]:")
            print(f"  По UUID ({len(res['uuid_references'])}):")
            for r in res["uuid_references"]:
                print(f"    • {r}")
            if res["name_references"]:
                print(f"  По имени ({len(res['name_references'])}):")
                for r in res["name_references"]:
                    print(f"    • {r}")
        else:
            print(f"Вхождения '{res['target']}' ({len(res['references'])}):")
            for r in res["references"]:
                print(f"  • {r}")


def cmd_tables(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        if src.kind != "1cd":
            print("Команда 'tables' работает только с файлами .1CD или .dt.", file=sys.stderr)
            sys.exit(1)
        _, items = load_metadata_index(src)
        mappings = resolve_table_mappings(src, items)
        stats = src.get_all_table_stats()
        table_to_label = mappings["table_to_label"]

        if args.json:
            out = []
            for tname, info in stats.items():
                if args.non_empty and info["non_empty"] == 0:
                    continue
                out.append(
                    {
                        "table": tname,
                        "non_empty": info["non_empty"],
                        "slots": info["slots"],
                        "metadata": table_to_label.get(tname, ""),
                        "fields": info["fields"],
                    }
                )
            _dump_json({"version": src.db.version, "locale": src.db.locale, "tables": out})
            return

        print(f"Формат БД: {src.db.version}, Язык: {src.db.locale}, Таблиц: {len(stats)}")
        for tname, info in stats.items():
            if args.non_empty and info["non_empty"] == 0:
                continue
            meta_desc = table_to_label.get(tname, "")
            extra = f" -> {meta_desc}" if meta_desc else ""
            print(f"  {tname:30} rows={info['non_empty']:5d} slots={info['slots']:5d}{extra}")


def cmd_rows(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        if src.kind != "1cd":
            print("Команда 'rows' работает только с файлами .1CD или .dt.", file=sys.stderr)
            sys.exit(1)
        _, items = load_metadata_index(src)
        mappings = resolve_table_mappings(src, items)
        table_to_colmap = mappings["table_to_colmap"]
        table_to_label = mappings["table_to_label"]
        lookup_index = mappings["lookup_index"]

        query = args.table_name.strip()
        table_name = None
        col_map: dict[str, str] = {}
        label = query

        if query in src.db.tables:
            table_name = query
            col_map = table_to_colmap.get(table_name, {})
            label = table_to_label.get(table_name, table_name)
        elif query.lower() in lookup_index:
            table_name, col_map, label = lookup_index[query.lower()]
        else:
            matches = find_matching_objects(items, query, class_filter=args.obj_class)
            if matches:
                det = parse_object_details(src, matches[0])
                if det["physical_table"] in src.db.tables:
                    table_name = det["physical_table"]
                    col_map = table_to_colmap.get(table_name, {})
                    label = table_to_label.get(table_name, matches[0]["name"])

        if not table_name or table_name not in src.db.tables:
            print(f"Таблица '{args.table_name}' не найдена в 1CD.", file=sys.stderr)
            sys.exit(1)

        rows = src.get_table_rows(table_name)
        slots = src.get_table_slots(table_name)
        fields = src.get_table_fields(table_name)
        ref_labels = {} if args.raw_refs else src.build_ref_labels(table_to_label)

        formatted_rows = []
        where_q = args.where.lower() if args.where else None
        for row in rows:
            rec = {}
            for col in fields:
                display_col = col_map.get(col, col)
                redact = table_name.upper() == "V8USERS" and col.upper() == "DATA"
                val = format_cell(row.get(col), redact=redact)
                if (
                    not args.raw_refs
                    and isinstance(val, str)
                    and val in ref_labels
                    and (col.endswith("RREF") or col == "_IDRREF")
                ):
                    val = f"{val} ({ref_labels[val]})"
                rec[display_col] = val
            if where_q and where_q not in json.dumps(rec, ensure_ascii=False).lower():
                continue
            formatted_rows.append(rec)
            if args.limit > 0 and len(formatted_rows) >= args.limit:
                break

        if args.json:
            _dump_json(
                {
                    "table": table_name,
                    "label": label,
                    "non_empty_total": len(rows),
                    "slots": slots,
                    "returned": len(formatted_rows),
                    "rows": formatted_rows,
                }
            )
            return

        print(f"Таблица: {table_name} [{label}] (записей: {len(rows)}, слотов: {slots}, показано: {len(formatted_rows)})")
        if not formatted_rows:
            print("  (Непустых записей нет)")
            return
        for rec in formatted_rows:
            print(json.dumps(rec, ensure_ascii=False))


def cmd_audit(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        report = run_audit(src, include_data=not args.no_data)
        if args.json:
            _dump_json(report)
            return
        cfg = report["config"]
        s = report["summary"]
        print(f"Аудит конфигурации: {cfg['name']} («{cfg['synonym']}»)")
        print(
            f"Проверено: модулей={report['modules_scanned']}, форм={report['forms_scanned']}, "
            f"ролей={report['roles_scanned']}"
        )
        print(f"Итого находок: {report['total_findings']} (ERROR={s['ERROR']}, WARNING={s['WARNING']}, INFO={s['INFO']})")
        for f in report["findings"]:
            print(f"\n[{f['severity']}] {f['category']} | {f['target']}")
            print(f"  {f['message']}")


def cmd_unpack(args: argparse.Namespace) -> None:
    ext = os.path.splitext(args.input_path)[1].lower()
    os.makedirs(args.output_dir, exist_ok=True)
    if ext == ".efd":
        onec_dtools.extract_efd(args.input_path, args.output_dir)
    else:
        onec_dtools.extract(args.input_path, args.output_dir)
    print(f"Распаковано в: {args.output_dir}")


def cmd_build(args: argparse.Namespace) -> None:
    onec_dtools.build(args.input_dir, args.output_path)
    print(f"Собрано в: {args.output_path}")


def cmd_raw(args: argparse.Namespace) -> None:
    with ConfigSource(args.path, args.table, args.force_reload) as src:
        if args.filename.upper() == "DBNAMES" and src.kind == "1cd":
            print(src.read_db_names_raw())
            return
        data = src.read_bytes(args.filename)
        if data is None:
            print(f"Файл '{args.filename}' не найден.", file=sys.stderr)
            sys.exit(1)
        if data.startswith(CONTAINER_MAGIC):
            cr = onec_dtools.ContainerReader(io.BytesIO(data))
            print(f"Вложенный контейнер, файлы: {list(cr.entries.keys())}")
            for ename, eobj in cr.entries.items():
                ed = decompress_1c(b"".join(eobj.data))
                print(f"\n--- {ename} ({len(ed)} bytes) ---")
                print(decode_text(ed))
        else:
            print(decode_text(data))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onec_tool",
        description="Универсальный инспектор файлов 1С:Предприятие 8 (.dt, .1CD, .cf, .cfe, .epf, .ert, .efd)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_flags(p: argparse.ArgumentParser, with_table: bool = True) -> None:
        p.add_argument("path", help="Путь к .dt, .1CD, .cf, .cfe, .epf, .ert, .efd или распакованному каталогу")
        if with_table:
            p.add_argument(
                "--table",
                default="CONFIG",
                help="Таблица конфигурации в .1CD (CONFIG или CONFIGSAVE)",
            )
        p.add_argument(
            "--force-reload",
            action="store_true",
            help="Принудительно перечитать .dt вместо кэша",
        )

    p_sum = sub.add_parser("summary", help="Обзор метаданных конфигурации (все классы и объекты)")
    add_common_flags(p_sum)
    p_sum.add_argument("--subsystems", action="store_true", help="Показать дерево подсистем")
    p_sum.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_sum.set_defaults(func=cmd_summary)

    p_sub = sub.add_parser("subsystems", help="Рекурсивное дерево подсистем и объектов вне подсистем")
    add_common_flags(p_sub)
    p_sub.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_sub.set_defaults(func=cmd_subsystems)

    p_obj = sub.add_parser("object", help="Детали объекта: реквизиты, типы, ТЧ, движения, перечисления, таблицы")
    add_common_flags(p_obj)
    p_obj.add_argument("query", help="Имя, подстрока имени (или Класс.Имя) или UUID объекта")
    p_obj.add_argument("--class", dest="obj_class", default=None, help="Фильтр по классу метаданных")
    p_obj.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_obj.set_defaults(func=cmd_object)

    p_mod = sub.add_parser("module", help="Извлечение BSL-кода модулей объекта, форм или всей конфигурации")
    add_common_flags(p_mod)
    p_mod.add_argument("query", nargs="?", default=None, help="Имя/UUID объекта (или Конфигурация)")
    p_mod.add_argument("--all", action="store_true", help="Извлечь все модули конфигурации")
    p_mod.add_argument("--list", action="store_true", help="Вывести только список модулей со счетчиком строк")
    p_mod.add_argument("--class", dest="obj_class", default=None, help="Фильтр по классу")
    p_mod.add_argument("--out", default=None, help="Сохранить код в файл или каталог")
    p_mod.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_mod.set_defaults(func=cmd_module)

    p_dcs = sub.add_parser("dcs", help="Разбор схем компоновки данных (СКД) отчетов и обработок")
    add_common_flags(p_dcs)
    p_dcs.add_argument("query", nargs="?", default=None, help="Имя отчета/обработки (или --all)")
    p_dcs.add_argument("--all", action="store_true", help="Разобрать СКД всех отчетов и обработок")
    p_dcs.add_argument("--xml", action="store_true", help="Включить исходный XML СКД")
    p_dcs.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_dcs.set_defaults(func=cmd_dcs)

    p_frm = sub.add_parser("forms", help="Инспекция управляемых и обычных форм (события, обработчики, процедуры)")
    add_common_flags(p_frm)
    p_frm.add_argument("query", nargs="?", default=None, help="Имя владельца/формы (или --all)")
    p_frm.add_argument("--all", action="store_true", help="Инспектировать все формы конфигурации")
    p_frm.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_frm.set_defaults(func=cmd_forms)

    p_rol = sub.add_parser("roles", help="Разбор ролей, прав на объекты и поиск дублей ролей")
    add_common_flags(p_rol)
    p_rol.add_argument("--details", action="store_true", help="Показать права по каждому объекту роли")
    p_rol.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_rol.set_defaults(func=cmd_roles)

    p_usr = sub.add_parser("users", help="Безопасное чтение таблицы V8USERS (поле DATA редактируется)")
    add_common_flags(p_usr, with_table=False)
    p_usr.set_defaults(table="CONFIG")
    p_usr.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_usr.set_defaults(func=cmd_users)

    p_src = sub.add_parser("search", help="Поиск текста по метаданным и BSL-модулям")
    add_common_flags(p_src)
    p_src.add_argument("query", help="Искомая строка")
    p_src.add_argument("--modules-only", action="store_true", help="Искать только внутри BSL-кода")
    p_src.add_argument("-i", "--ignore-case", action="store_true", help="Регистронезависимый поиск")
    p_src.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_src.set_defaults(func=cmd_search)

    p_xrf = sub.add_parser("xref", help="Поиск ссылок на объект или обнаружение неиспользуемых объектов")
    add_common_flags(p_xrf)
    p_xrf.add_argument("query", nargs="?", default=None, help="Имя/UUID объекта (оставьте пустым с --unused)")
    p_xrf.add_argument("--unused", action="store_true", help="Найти объекты без внешних ссылок")
    p_xrf.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_xrf.set_defaults(func=cmd_xref)

    p_tbl = sub.add_parser("tables", help="Список таблиц .1CD (точные непустые строки + слоты) и маппинг DBNames")
    add_common_flags(p_tbl, with_table=False)
    p_tbl.set_defaults(table="CONFIG")
    p_tbl.add_argument("--non-empty", action="store_true", help="Показать только непустые таблицы")
    p_tbl.add_argument("--all-stats", action="store_true", help="Алиас подсчета всех таблиц (включен по умолчанию)")
    p_tbl.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_tbl.set_defaults(func=cmd_tables)

    p_rows = sub.add_parser("rows", help="Чтение строк таблицы .1CD (включая ТЧ Объект.ТЧ и расшифровку ссылок)")
    add_common_flags(p_rows, with_table=False)
    p_rows.set_defaults(table="CONFIG")
    p_rows.add_argument("table_name", help="Физическая таблица (_DOCUMENT334_VT345), Объект или Объект.ТЧ")
    p_rows.add_argument("--limit", type=int, default=20, help="Максимум строк (0 = без лимита)")
    p_rows.add_argument("--class", dest="obj_class", default=None, help="Фильтр класса при поиске объекта")
    p_rows.add_argument("--raw-refs", action="store_true", help="Не подставлять человекочитаемые имена к GUID-ссылкам")
    p_rows.add_argument("--where", default=None, help="Фильтр строк по подстроке")
    p_rows.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_rows.set_defaults(func=cmd_rows)

    p_aud = sub.add_parser("audit", help="Универсальная диагностика конфигурации, BSL, форм, ролей и данных ИБ")
    add_common_flags(p_aud)
    p_aud.add_argument("--no-data", action="store_true", help="Не анализировать таблицы данных ИБ (.1CD/.dt)")
    p_aud.add_argument("--json", action="store_true", help="Вывод в JSON")
    p_aud.set_defaults(func=cmd_audit)

    p_unp = sub.add_parser("unpack", help="Распаковать .cf/.cfe/.epf/.ert/.efd в каталог")
    p_unp.add_argument("input_path", help="Путь к контейнеру или .efd")
    p_unp.add_argument("output_dir", help="Целевой каталог")
    p_unp.set_defaults(func=cmd_unpack)

    p_bld = sub.add_parser("build", help="Собрать каталог обратно в контейнер .cf/.epf/.ert")
    p_bld.add_argument("input_dir", help="Исходный каталог")
    p_bld.add_argument("output_path", help="Выходной файл контейнера")
    p_bld.set_defaults(func=cmd_build)

    p_raw = sub.add_parser("raw", help="Прочитать внутренний файл конфигурации по имени/UUID")
    add_common_flags(p_raw)
    p_raw.add_argument("filename", help="Имя файла (например root, DBNames или UUID)")
    p_raw.set_defaults(func=cmd_raw)

    return parser


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

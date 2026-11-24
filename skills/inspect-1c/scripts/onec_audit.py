"""Universal, configuration-agnostic 1C static & infobase diagnostic engine."""

from __future__ import annotations

import re
from typing import Any

from onec_core import ConfigSource, UUID_RE, clean_text
from onec_meta import (
    build_type_uuid_map,
    collect_all_modules,
    find_xrefs,
    load_metadata_index,
    load_subsystems_tree,
    parse_forms,
    parse_object_details,
    parse_roles,
    read_users_safe,
    resolve_table_mappings,
)

# Built-in platform methods on Enums.<EnumName>.<Method> that are NOT enum values
ENUM_MANAGER_METHODS = {
    "пустаяссылка",
    "индекс",
    "получить",
    "количество",
    "найтипоимени",
    "emptyref",
    "index",
    "get",
    "count",
    "findbyname",
}

METADATA_COLLECTION_PREFIXES = {
    "Справочники": "Справочники",
    "Документы": "Документы",
    "РегистрыНакопления": "Регистры накопления",
    "РегистрыСведений": "Регистры сведений",
    "Константы": "Константы",
    "Отчеты": "Отчеты",
    "Обработки": "Обработки",
    "ОбщиеМодули": "Общие модули",
    "Перечисления": "Перечисления",
    "ПланыВидовХарактеристик": "Планы видов характеристик",
    "ПланыСчетов": "Планы счетов",
    "БизнесПроцессы": "Бизнес-процессы",
    "Задачи": "Задачи",
    "ЖурналыДокументов": "Журналы документов",
}

ENUM_REF_RE = re.compile(
    r"(?:Перечисления|Enums)\.([A-Za-zА-Яа-яЁё0-9_]+)\.([A-Za-zА-Яа-яЁё0-9_]+)"
)
META_PREFIX_RE = re.compile(
    r"\b(" + "|".join(METADATA_COLLECTION_PREFIXES.keys()) + r")\.([A-Za-zА-Яа-яЁё0-9_]+)"
)
MODAL_CALL_RE = re.compile(
    r"(?<![A-Za-zА-Яа-яЁё0-9_.])(Вопрос|Предупреждение|ВвестиСтроку|ВвестиЧисло|ВвестиДату|ОткрытьЗначение|ВыбратьЗначение)\s*\(",
    re.IGNORECASE,
)
DYNAMIC_EXEC_RE = re.compile(
    r"(?<![A-Za-zА-Яа-яЁё0-9_.])(Выполнить|Вычислить|Execute|Eval)\s*\(",
    re.IGNORECASE,
)


def _strip_bsl_comments_and_strings(code: str) -> str:
    """Strips BSL comments (//...) and string literals for low-false-positive scanning."""
    out_lines: list[str] = []
    for line in code.splitlines():
        # Strip literal strings crudely first, then // comments
        cleaned = re.sub(r'"(?:[^"]|"")*"', '""', line)
        idx = cleaned.find("//")
        if idx >= 0:
            cleaned = cleaned[:idx]
        out_lines.append(cleaned)
    return "\n".join(out_lines)


def _scan_loops_for_queries(code: str) -> list[int]:
    """Detects .Выполнить() / .Execute() inside BSL Пока/Для loops."""
    hits: list[int] = []
    loop_depth = 0
    for lineno, raw_line in enumerate(code.splitlines(), 1):
        line = re.sub(r'"(?:[^"]|"")*"', '""', raw_line)
        idx = line.find("//")
        if idx >= 0:
            line = line[:idx]
        low = line.strip().lower()
        if not low:
            continue
        if re.match(r"^(пока|для|while|for)\b", low):
            loop_depth += 1
        if loop_depth > 0 and re.search(r"\.(выполнить|выполнитьпакет|execute|executebatch)\s*\(", low):
            hits.append(lineno)
        if re.match(r"^(конеццикла|enddo)\b", low) and loop_depth > 0:
            loop_depth -= 1
    return hits


def _scan_empty_excepts(code: str) -> list[int]:
    """Detects empty 'Исключение ... КонецПопытки' blocks swallowing errors silently."""
    hits: list[int] = []
    lines = code.splitlines()
    in_except = False
    except_line = 0
    has_stmt = False
    for lineno, raw in enumerate(lines, 1):
        idx = raw.find("//")
        s = (raw[:idx] if idx >= 0 else raw).strip().lower()
        if not s:
            continue
        if re.match(r"^(исключение|except)\b", s):
            in_except = True
            except_line = lineno
            has_stmt = False
            continue
        if in_except:
            if re.match(r"^(конецпопытки|endtry)\b", s):
                if not has_stmt:
                    hits.append(except_line)
                in_except = False
            else:
                has_stmt = True
    return hits


def run_audit(src: ConfigSource, include_data: bool = True) -> dict[str, Any]:
    """Executes universal diagnostics on any 1C configuration and optional .1CD data."""
    cfg, items = load_metadata_index(src)
    type_map = build_type_uuid_map(src, items)
    findings: list[dict[str, Any]] = []

    def add(severity: str, category: str, target: str, message: str) -> None:
        findings.append(
            {
                "severity": severity,  # ERROR | WARNING | INFO
                "category": category,
                "target": target,
                "message": clean_text(message),
            }
        )

    # Parse all non-image objects once
    details_by_uuid: dict[str, dict[str, Any]] = {}
    names_by_class: dict[str, set[str]] = {}
    enum_values_map: dict[str, set[str]] = {}
    for it in items:
        if it["class_name"] == "Общие картинки":
            continue
        names_by_class.setdefault(it["class_name"], set()).add(it["name"].lower())
        det = parse_object_details(src, it, type_map)
        details_by_uuid[it["uuid"]] = det
        if it["class_name"] == "Перечисления":
            enum_values_map[it["name"].lower()] = {
                ev["name"].lower() for ev in det.get("enum_values", [])
            }

    # 1. Subsystem & structural hygiene checks
    sub_info = load_subsystems_tree(src, items)
    for obj in sub_info["unassigned_business_objects"]:
        add(
            "INFO",
            "Структура/Подсистемы",
            f"{obj['class_name']}.{obj['name']}",
            "Объект не включён ни в одну подсистему.",
        )

    def _check_empty_sub(node: dict[str, Any], path: str = "") -> None:
        cur = f"{path}/{node['name']}" if path else node["name"]
        if not node["objects"] and not node["children"]:
            add("INFO", "Структура/Подсистемы", cur, "Пустая подсистема без объектов и дочерних подсистем.")
        for ch in node["children"]:
            _check_empty_sub(ch, cur)

    for sroot in sub_info["subsystems"]:
        _check_empty_sub(sroot)

    # 2. Unreferenced / unused metadata objects
    xref_unused = find_xrefs(src, cfg, items, unused_only=True)
    for uo in xref_unused["unused_objects"]:
        add(
            "WARNING",
            "Неиспользуемый объект",
            f"{uo['class_name']}.{uo['name']}",
            "Внешних ссылок на объект в метаданных, формах, ролях, СКД и BSL-модулях не обнаружено.",
        )

    # 3. Collect all BSL modules & inspect statically
    modules = collect_all_modules(src, cfg, items)
    modules_by_owner_uuid: dict[str, list[dict[str, Any]]] = {}
    all_bsl_clean_parts: list[str] = []
    for mod in modules:
        modules_by_owner_uuid.setdefault(mod["owner_uuid"], []).append(mod)
        code = mod["code"]
        cleaned = _strip_bsl_comments_and_strings(code)
        all_bsl_clean_parts.append(cleaned)

        # 3a. Invalid Enum references: Перечисления.<Enum>.<Value>
        for ename, eval_name in ENUM_REF_RE.findall(cleaned):
            el = ename.lower()
            vl = eval_name.lower()
            if el not in enum_values_map:
                add(
                    "ERROR",
                    "BSL/Перечисления",
                    mod["title"],
                    f"Обращение к несуществующему перечислению Перечисления.{ename}.{eval_name}.",
                )
            elif vl not in ENUM_MANAGER_METHODS and enum_values_map[el] and vl not in enum_values_map[el]:
                add(
                    "ERROR",
                    "BSL/Перечисления",
                    mod["title"],
                    f"Несуществующее значение перечисления: Перечисления.{ename}.{eval_name}.",
                )

        # 3b. Invalid Metadata object references: Справочники.<X>, Документы.<Y>, ...
        for prefix, obj_ref in META_PREFIX_RE.findall(cleaned):
            cls_ru = METADATA_COLLECTION_PREFIXES[prefix]
            if obj_ref.lower() not in names_by_class.get(cls_ru, set()):
                add(
                    "ERROR",
                    "BSL/Метаданные",
                    mod["title"],
                    f"Ссылка на отсутствующий объект метаданных: {prefix}.{obj_ref}.",
                )

        # 3c. Synchronous modal calls, Dynamic Execute, Queries in Loops, Silent Excepts
        modals = sorted(set(MODAL_CALL_RE.findall(cleaned)))
        if modals:
            add(
                "WARNING",
                "BSL/Модальность",
                mod["title"],
                f"Использование синхронных/модальных вызовов: {', '.join(modals)} (может не работать при отключённой модальности).",
            )

        dyn = sorted(set(DYNAMIC_EXEC_RE.findall(cleaned)))
        if dyn:
            add(
                "WARNING",
                "BSL/Безопасность",
                mod["title"],
                f"Динамическое выполнение кода ({', '.join(dyn)}).",
            )

        loop_q = _scan_loops_for_queries(code)
        if loop_q:
            add(
                "WARNING",
                "BSL/Производительность",
                mod["title"],
                f"Выполнение запроса внутри цикла (строки: {', '.join(map(str, loop_q[:10]))}).",
            )

        empty_ex = _scan_empty_excepts(code)
        if empty_ex:
            add(
                "WARNING",
                "BSL/ОбработкаОшибок",
                mod["title"],
                f"Пустой блок Исключение..КонецПопытки без обработки ошибки (строки: {', '.join(map(str, empty_ex[:10]))}).",
            )

    all_bsl_clean = "\n".join(all_bsl_clean_parts)

    # 4. Document RegisterRecords vs ОбработкаПроведения consistency + orphaned registers
    declared_writer_uuids: set[str] = set()
    by_uuid = {i["uuid"]: i for i in items}
    for it in items:
        if it["class_name"] != "Документы":
            continue
        det = details_by_uuid.get(it["uuid"], {})
        reg_recs = det.get("register_records", [])
        for rr in reg_recs:
            declared_writer_uuids.add(rr["uuid"])
        if not reg_recs:
            continue
        obj_mods = [
            m for m in modules_by_owner_uuid.get(it["uuid"], [])
            if m["filename"].endswith(".0")
        ]
        obj_code = "\n".join(m["code"] for m in obj_mods)
        if not obj_code.strip():
            add(
                "WARNING",
                "Документы/Движения",
                f"Документы.{it['name']}",
                f"Указаны движения по регистрам ({', '.join(r['label'] for r in reg_recs)}), но отсутствует МодульОбъекта.",
            )
            continue
        for rr in reg_recs:
            reg_obj = by_uuid.get(rr["uuid"])
            reg_name = reg_obj["name"] if reg_obj else rr["label"].split(".")[-1]
            if not re.search(rf"Движения\s*\.\s*{re.escape(reg_name)}\b", obj_code, re.I):
                add(
                    "WARNING",
                    "Документы/Движения",
                    f"Документы.{it['name']}",
                    f"Регистр '{rr['label']}' указан в Движениях метаданных, но не формируется через Движения.{reg_name} в МодулеОбъекта.",
                )

    for it in items:
        if it["class_name"] not in ("Регистры накопления", "Регистры сведений", "Регистры бухгалтерии", "Регистры расчета"):
            continue
        is_declared = it["uuid"] in declared_writer_uuids
        has_bsl_mention = bool(re.search(rf"\b{re.escape(it['name'])}\b", all_bsl_clean))
        if not is_declared and not has_bsl_mention:
            add(
                "WARNING",
                "Регистры/Запись",
                f"{it['class_name']}.{it['name']}",
                "Регистр не указан в движениях документов и не упоминается в BSL-коде.",
            )

    # 5. Form binding checks (events declared on form without handler in form BSL)
    forms = parse_forms(src, items)
    for frm in forms:
        for mh in frm["missing_handlers"]:
            add(
                "ERROR",
                "Формы/Обработчики",
                f"{frm['owner_class']}.{frm['owner_name']}.{frm['form_name']}",
                f"Событие '{mh['event']}' ссылается на отсутствующую процедуру '{mh['handler']}' в модуле формы.",
            )

    # 6. Numeric precision mismatch detection across Documents/Catalogs <-> Registers
    reg_numeric_fields: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    doc_cat_numeric_fields: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for it in items:
        det = details_by_uuid.get(it["uuid"])
        if not det:
            continue
        target_bucket = None
        if it["class_name"] in ("Регистры накопления", "Регистры сведений", "Регистры бухгалтерии"):
            target_bucket = reg_numeric_fields
        elif it["class_name"] in ("Документы", "Справочники"):
            target_bucket = doc_cat_numeric_fields
        if target_bucket is None:
            continue
        for attr in det.get("attributes", []):
            num = attr.get("numeric")
            if not num:
                continue
            fname_low = attr["name"].lower()
            loc = f"{it['class_name']}.{it['name']}.{attr['parent_ts'] + '.' if attr.get('parent_ts') else ''}{attr['name']}"
            target_bucket.setdefault(fname_low, []).append((loc, num))

    for fname_low, reg_specs in reg_numeric_fields.items():
        for reg_loc, rnum in reg_specs:
            # Flag zero-precision Price/Sum-like fields inside registers as suspicious if paired with fractional docs
            for src_loc, dnum in doc_cat_numeric_fields.get(fname_low, []):
                if (dnum["precision"] or 0) > (rnum["precision"] or 0):
                    add(
                        "ERROR",
                        "ТочностьТипов",
                        f"{src_loc} -> {reg_loc}",
                        f"Потеря точности дробной части: источник Число({dnum['length']},{dnum['precision']}) vs регистр Число({rnum['length']},{rnum['precision']}).",
                    )
                elif dnum["length"] and rnum["length"] and dnum["length"] > rnum["length"]:
                    add(
                        "WARNING",
                        "ТочностьТипов",
                        f"{src_loc} -> {reg_loc}",
                        f"Разная длина числа: источник Число({dnum['length']},{dnum['precision']}) > регистр Число({rnum['length']},{rnum['precision']}).",
                    )

    # 7. Roles hygiene checks
    roles_info = parse_roles(src, cfg, items)
    for dup_grp in roles_info["duplicate_groups"]:
        add(
            "WARNING",
            "Роли",
            ", ".join(dup_grp),
            f"Роли побайтно идентичны по набору прав ({len(dup_grp)} ролей с одинаковым .0 файлом).",
        )
    for role in roles_info["roles"]:
        if role["objects_count"] == 0 and not role.get("set_rights_for_new_objects"):
            add("INFO", "Роли", role["name"], "Роль не содержит ни одной записи прав.")

    # 8. Infobase (.1CD / .dt) checks
    if src.kind == "1cd" and include_data:
        users_info = read_users_safe(src)
        if users_info.get("supported"):
            if users_info["count"] == 0:
                add("INFO", "Пользователи/V8USERS", "V8USERS", "Список пользователей ИБ пуст.")
            for u in users_info["users"]:
                uname = str(u.get("NAME") or "")
                adm = u.get("ADMROLE")
                eauth = u.get("EAUTH")
                if adm is True and not any(k in uname.lower() for k in ("admin", "админ", "root", "sys")):
                    add(
                        "WARNING",
                        "Пользователи/V8USERS",
                        uname,
                        f"Пользователю '{uname}' выданы полные административные права (ADMROLE=True, EAUTH={eauth}). Проверьте обоснованность.",
                    )

        # Table data sanity: Posted documents vs physical register rows
        stats = src.get_all_table_stats()
        mappings = resolve_table_mappings(src, items, type_map)
        doc_posted_counts: dict[str, int] = {}
        for it in items:
            if it["class_name"] != "Документы":
                continue
            det = details_by_uuid.get(it["uuid"], {})
            pt = det.get("physical_table")
            if pt and pt in stats:
                rows = src.get_table_rows(pt)
                posted = sum(1 for r in rows if r.get("_POSTED") is True)
                doc_posted_counts[it["uuid"]] = posted

        for it in items:
            if it["class_name"] != "Документы":
                continue
            posted = doc_posted_counts.get(it["uuid"], 0)
            if posted <= 0:
                continue
            det = details_by_uuid.get(it["uuid"], {})
            for rr in det.get("register_records", []):
                r_det = details_by_uuid.get(rr["uuid"], {})
                rpt = r_det.get("physical_table")
                if rpt and rpt in stats and stats[rpt]["non_empty"] == 0:
                    add(
                        "WARNING",
                        "ДанныеИБ/Движения",
                        f"Документы.{it['name']} -> {rr['label']}",
                        f"В ИБ есть проведённые документы ({posted} шт.), но таблица регистра {rpt} содержит 0 записей.",
                    )

    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "config": cfg,
        "summary": counts,
        "total_findings": len(findings),
        "modules_scanned": len(modules),
        "forms_scanned": len(forms),
        "roles_scanned": len(roles_info["roles"]),
        "findings": findings,
    }

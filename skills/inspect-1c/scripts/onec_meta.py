"""Universal 1C metadata, subsystems, DCS (SKD), forms, roles, users, and cross-ref parsers."""

from __future__ import annotations

import hashlib
import html
import io
import re
import xml.etree.ElementTree as ET
from typing import Any

import onec_dtools

from onec_core import (
    BSL_KEYWORDS,
    CLASS_NAMES,
    CONTAINER_MAGIC,
    UUID_RE,
    ConfigSource,
    clean_text,
    decode_text,
    decompress_1c,
    format_cell,
    parse_v8_tree,
    pick_primary_table,
)

# Standard 1C metadata section UUIDs for richer categorization (falls back structurally when unknown)
SECTION_KIND_MAP: dict[str, str] = {
    "cf4abea7-37b2-11d4-940f-008048da11f9": "Реквизит",
    "45e46cbc-3e24-4165-8b7b-cc98a6f80211": "Реквизит",
    "21c53e09-8950-4b5e-a6a0-1054f1bbc274": "Табличная часть",
    "932159f9-95b2-4e76-a8dd-8849fe5c5ded": "Табличная часть",
    "b64d9a41-1642-11d6-a3c7-0050bae0a776": "Ресурс",
    "b64d9a42-1642-11d6-a3c7-0050bae0a776": "Реквизит",
    "b64d9a43-1642-11d6-a3c7-0050bae0a776": "Измерение",
    "13134202-f60b-11d5-a3c7-0050bae0a776": "Ресурс",
    "13134203-f60b-11d5-a3c7-0050bae0a776": "Измерение",
    "13134204-f60b-11d5-a3c7-0050bae0a776": "Реквизит",
    "bee0a08c-07eb-40c0-8544-5c364c171465": "Значение перечисления",
    "3daea016-69b7-4ed4-9453-127911372fe6": "Команда",
    "fb880e93-47d7-4127-9357-a20e69c17545": "Форма",
    "fdf816d2-1ead-11d5-b975-0050bae0a95d": "Форма",
    "b44ba719-945c-445c-8aab-1088fa4df16e": "Форма",
    "6d8d73a7-ba29-401d-9032-3872ec2d6433": "Форма",
    "b544fc6a-2ba3-4885-8fb2-cb289fb6d65e": "Макет",
    "4fe87c89-9ad4-43f6-9fdb-9dc83b3879c6": "Макет",
    "a2207540-1400-11d6-a3c7-0050bae0a776": "Макет",
    "33f2e54b-37ce-4a7a-a569-b648d7aa4634": "Макет",
}

BUILTIN_TYPE_UUIDS: dict[str, str] = {
    "fc01b5df-97fe-449b-83d4-218a090e681e": "УникальныйИдентификатор",
    "157fa490-4ce9-11d4-9415-008048da11f9": "ОбъектМетаданных",
    "f5c65050-3bbb-11d5-b988-0050bae0a95d": "ХранилищеЗначения",
    "9cd510d0-abfc-11d4-9434-004095e12fc7": "Граница",
}

METADATA_REF_UUID = "157fa490-4ce9-11d4-9415-008048da11f9"

NON_BUSINESS_CLASSES = {
    "Языки",
    "Стили",
    "Общие картинки",
    "Роли",
    "Подсистемы",
    "Общие модули",
    "Общие формы",
    "Общие макеты",
    "Общие команды",
    "Группы команд",
    "Параметры функциональных опций",
    "Функциональные опции",
    "Общие реквизиты",
    "Критерии отбора",
    "Пакеты XDTO",
    "Определяемые типы",
}

PROC_DEF_RE = re.compile(
    r"^\s*(?:Процедура|Функция|Procedure|Function)\s+([A-Za-zА-Яа-яЁё_][A-Za-zА-Яа-яЁё0-9_]*)\s*\(",
    re.IGNORECASE | re.MULTILINE,
)


def extract_object_name(text: str) -> tuple[str, str]:
    """Extracts identifier and Russian synonym from a 1C metadata object header."""
    if not text:
        return "", ""
    m = re.search(
        r'\{1,0,[0-9a-f-]{36}\}\s*,\s*"([^"]+)"\s*,\s*\{\s*1\s*,\s*"ru"\s*,\s*"((?:[^"]|"")*)"',
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2).replace('""', '"')
    m2 = re.search(r'\{1,0,[0-9a-f-]{36}\}\s*,\s*"([^"]+)"', text, re.IGNORECASE)
    if m2:
        return m2.group(1), ""
    return "", ""


def extract_object_comment(text: str) -> str:
    """Extracts optional object Comment string immediately after synonym block."""
    if not text:
        return ""
    m = re.search(
        r'\{1,0,[0-9a-f-]{36}\}\s*,\s*"[^"]+"\s*,\s*\{[^}]*\}\s*,\s*"((?:[^"]|"")*)"',
        text,
        re.IGNORECASE,
    )
    if m:
        return clean_text(m.group(1).replace('""', '"'))
    return ""


def load_metadata_index(src: ConfigSource) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Loads configuration root info and all metadata objects grouped by class."""
    root_text = src.read_text("root")
    if not root_text:
        raise RuntimeError("Отсутствует запись 'root' в источнике конфигурации.")
    uuids = UUID_RE.findall(root_text)
    if not uuids:
        raise RuntimeError("Не найден корневой UUID метаданных внутри 'root'.")
    root_uuid = uuids[0].lower()
    meta_text = src.read_text(root_uuid)
    if not meta_text:
        raise RuntimeError(f"Отсутствует файл корневых метаданных '{root_uuid}'.")

    cfg_name, cfg_syn = extract_object_name(meta_text[:1500])
    config_info = {
        "uuid": root_uuid,
        "name": cfg_name,
        "synonym": cfg_syn,
        "comment": extract_object_comment(meta_text[:1500]),
    }

    sections = re.findall(
        r"\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}),\s*(\d+)(.*?)\}",
        meta_text,
        re.S | re.I,
    )

    items: list[dict[str, str]] = []
    seen_uids: set[str] = set()
    for class_id, count_s, body in sections:
        count = int(count_s)
        if count == 0:
            continue
        cid = class_id.lower()
        cname = CLASS_NAMES.get(cid, f"Класс ({cid})")
        for item_uuid in UUID_RE.findall(body):
            uid = item_uuid.lower()
            if uid in seen_uids:
                continue
            seen_uids.add(uid)
            obj_text = src.read_text(uid) or ""
            name, syn = extract_object_name(obj_text)
            items.append(
                {
                    "uuid": uid,
                    "class_id": cid,
                    "class_name": cname,
                    "name": name or f"<{uid}>",
                    "synonym": syn,
                }
            )

    if not items and cfg_name:
        items.append(
            {
                "uuid": root_uuid,
                "class_id": "external",
                "class_name": "Внешний объект (.epf/.ert)",
                "name": cfg_name,
                "synonym": cfg_syn,
            }
        )
    return config_info, items


def find_matching_objects(
    items: list[dict[str, str]], query: str, class_filter: str | None = None
) -> list[dict[str, str]]:
    """Matches objects by UUID, exact name, or substring, optionally filtered by class."""
    q = query.strip().lower()
    pool = items
    if class_filter:
        cf = class_filter.strip().lower()
        pool = [i for i in items if cf in i["class_name"].lower()]

    exact_uuid = [i for i in pool if i["uuid"].lower() == q]
    if exact_uuid:
        return exact_uuid

    if "." in q:
        cls_part, name_part = q.split(".", 1)
        qualified = [
            i for i in pool
            if cls_part in i["class_name"].lower() and i["name"].lower() == name_part
        ]
        if qualified:
            return qualified

    exact_name = [i for i in pool if i["name"].lower() == q]
    if exact_name:
        return exact_name

    partial = [i for i in pool if q in i["name"].lower() or q in i["synonym"].lower()]
    if partial or not class_filter:
        return partial
    # Fallback without class filter only if filtered search was empty? No, respect filter
    return []


def build_type_uuid_map(src: ConfigSource, items: list[dict[str, str]]) -> dict[str, str]:
    """Maps each object's internal serialization type UUIDs to 'ClassName.ObjectName'."""
    tmap = dict(BUILTIN_TYPE_UUIDS)
    for it in items:
        if it["class_name"] == "Общие картинки":
            continue
        txt = src.read_text(it["uuid"])
        if not txt:
            continue
        marker = it["uuid"]
        idx = txt.lower().find(marker)
        head = txt[:idx] if idx > 0 else txt[:1000]
        label = f"{it['class_name']}.{it['name']}"
        tmap[it["uuid"]] = label
        for u in UUID_RE.findall(head):
            ul = u.lower()
            if ul != "00000000-0000-0000-0000-000000000000" and ul not in tmap:
                tmap[ul] = label
    return tmap


def decode_pattern(pattern_node: Any, type_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Decodes a 1C ['Pattern', ...] node into human-readable type info and numeric precision."""
    if not isinstance(pattern_node, list) or not pattern_node or pattern_node[0] != "Pattern":
        return {"summary": "", "types": [], "numeric": None}

    types: list[str] = []
    numeric_info: dict[str, Any] | None = None
    tmap = type_map or {}

    for entry in pattern_node[1:]:
        if not isinstance(entry, list) or not entry:
            continue
        tag = entry[0]
        if tag == "S":
            if len(entry) >= 2 and str(entry[1]).isdigit() and int(entry[1]) > 0:
                types.append(f"Строка({entry[1]})")
            else:
                types.append("Строка")
        elif tag == "N":
            length = int(entry[1]) if len(entry) >= 2 and str(entry[1]).lstrip("-").isdigit() else None
            prec = int(entry[2]) if len(entry) >= 3 and str(entry[2]).lstrip("-").isdigit() else 0
            nonneg = bool(len(entry) >= 4 and str(entry[3]) == "0")
            types.append(f"Число({length},{prec})" if length is not None else "Число")
            if numeric_info is None:
                numeric_info = {"length": length, "precision": prec, "nonnegative": nonneg}
        elif tag == "D":
            mode = entry[1] if len(entry) >= 2 else ""
            types.append(f"Дата({mode})" if mode in ("D", "T") else "Дата")
        elif tag == "B":
            types.append("Булево")
        elif tag == "#":
            uid = str(entry[1]).lower() if len(entry) >= 2 else ""
            if uid == "00000000-0000-0000-0000-000000000000":
                types.append("ЛюбаяСсылка")
            else:
                types.append(tmap.get(uid, f"Тип:{uid}"))
        else:
            types.append(str(tag))

    return {
        "summary": " | ".join(types) if types else "",
        "types": types,
        "numeric": numeric_info,
    }


def _find_first_pattern(node: Any) -> list[Any] | None:
    """Finds ['Pattern', ...] shallowly inside an attribute metadata node."""
    if not isinstance(node, list):
        return None
    if node and node[0] == "Pattern":
        return node
    for el in node:
        if isinstance(el, list):
            if el and el[0] == "Pattern":
                return el
            res = _find_first_pattern(el)
            if res is not None:
                return res
    return None


def _find_ident_header(node: Any) -> tuple[str, str, str, str] | None:
    """Finds {1,0,uuid},"Name",{1,"ru","Syn"},"Desc" inside a node without recursing into sibling items."""
    if not isinstance(node, list):
        return None
    # Direct match on [..., ['1','0',uuid], name, syn_block, desc, ...]
    for i, el in enumerate(node):
        if (
            isinstance(el, list)
            and len(el) >= 3
            and el[0] == "1"
            and el[1] == "0"
            and isinstance(el[2], str)
            and UUID_RE.fullmatch(el[2])
        ):
            uid = el[2].lower()
            name = str(node[i + 1]) if i + 1 < len(node) and isinstance(node[i + 1], str) else ""
            syn = ""
            if i + 2 < len(node) and isinstance(node[i + 2], list):
                sb = node[i + 2]
                if len(sb) >= 3 and sb[1] == "ru":
                    syn = str(sb[2])
            desc = str(node[i + 3]) if i + 3 < len(node) and isinstance(node[i + 3], str) else ""
            if name:
                return uid, name, clean_text(syn), clean_text(desc)
    for el in node:
        if isinstance(el, list):
            res = _find_ident_header(el)
            if res is not None:
                return res
    return None


def _extract_attr_entry(
    node: Any,
    db_names: dict[str, list[tuple[str, str]]],
    type_map: dict[str, str],
    default_kind: str,
    parent_ts: str | None = None,
) -> dict[str, Any] | None:
    hdr = _find_ident_header(node)
    if not hdr:
        return None
    suid, sname, ssyn, sdesc = hdr
    pat = _find_first_pattern(node)
    type_info = decode_pattern(pat, type_map) if pat else {"summary": "", "types": [], "numeric": None}
    f_entries = db_names.get(suid, [])
    phys_col = f"_{f_entries[0][0].upper()}{f_entries[0][1]}" if f_entries else None
    return {
        "name": sname,
        "synonym": ssyn,
        "description": sdesc,
        "uuid": suid,
        "kind": default_kind,
        "type": type_info["summary"],
        "types": type_info["types"],
        "numeric": type_info["numeric"],
        "physical_col": phys_col,
        "parent_ts": parent_ts,
    }


def extract_config_properties(src: ConfigSource, cfg: dict[str, str]) -> dict[str, Any]:
    """Extracts root configuration properties and attached root modules."""
    root_txt = src.read_text(cfg["uuid"]) or ""
    tree = parse_v8_tree(root_txt)
    strings: list[str] = []
    if isinstance(tree, list):
        # Scan top-level and header strings for copyright / version / brief info
        def _collect_str(n: Any, depth: int = 0) -> None:
            if depth > 4:
                return
            if isinstance(n, str) and len(n) >= 2 and not UUID_RE.fullmatch(n) and not n.isdigit():
                strings.append(n)
            elif isinstance(n, list):
                for x in n[:40]:
                    _collect_str(x, depth + 1)

        _collect_str(tree)

    root_mods = []
    suffix_names = {
        "0": "МодульУправляемогоПриложения / МодульОбычногоПриложения",
        "1": "МодульСеанса",
        "2": "МодульВнешнегоСоединения",
        "6": "МодульПриложения / Расширение",
        "7": "МодульСеанса",
    }
    for fn in src.list_files():
        if fn.startswith(cfg["uuid"] + "."):
            suf = fn.split(".", 1)[1]
            code = read_bsl_from_file(src, fn)
            if code and code.strip():
                root_mods.append(
                    {
                        "filename": fn,
                        "suffix": suf,
                        "title": suffix_names.get(suf, f"МодульКонфигурации (.{suf})"),
                        "lines": len(code.splitlines()),
                    }
                )

    return {
        "uuid": cfg["uuid"],
        "name": cfg["name"],
        "synonym": cfg["synonym"],
        "comment": cfg.get("comment", ""),
        "header_strings": strings[:15],
        "root_modules": root_mods,
    }


def parse_object_details(
    src: ConfigSource, item: dict[str, str], type_map: dict[str, str] | None = None
) -> dict[str, Any]:
    """Extracts attributes, tabular sections, register specs, enums, flags, and DB mapping."""
    uid = item["uuid"]
    text = src.read_text(uid) or ""
    db_names = src.get_db_names()
    db_entries = db_names.get(uid, [])
    phys_table = pick_primary_table(db_entries)
    all_phys_tables = [f"_{k.upper()}{n}" for k, n in db_entries]
    tmap = type_map or {}

    attributes: list[dict[str, Any]] = []
    tabular_sections: list[dict[str, Any]] = []
    enum_values: list[dict[str, str]] = []
    child_uuids_typed: list[tuple[str, str]] = []
    seen_sub: set[str] = set()

    tree = parse_v8_tree(text)
    if isinstance(tree, list):
        for el in tree:
            if not (isinstance(el, list) and len(el) >= 2 and isinstance(el[0], str) and UUID_RE.fullmatch(el[0])):
                continue
            sec_uid = el[0].lower()
            sec_kind = SECTION_KIND_MAP.get(sec_uid, "Элемент")
            items_nodes = el[2:]

            # Child references stored directly as UUID strings (Forms, Commands, Templates)
            if items_nodes and all(isinstance(x, str) and UUID_RE.fullmatch(x) for x in items_nodes):
                for cu in items_nodes:
                    child_uuids_typed.append((cu.lower(), sec_kind))
                continue

            if sec_kind == "Табличная часть" or (
                sec_kind == "Элемент" and any(_looks_like_tabular_section(x) for x in items_nodes)
            ):
                for ts_node in items_nodes:
                    ts_hdr = _find_ident_header(ts_node)
                    if not ts_hdr:
                        continue
                    ts_uid, ts_name, ts_syn, ts_desc = ts_hdr
                    if ts_uid in seen_sub or ts_uid == uid:
                        continue
                    seen_sub.add(ts_uid)
                    ts_db = db_names.get(ts_uid, [])
                    vt_suffix = f"_{ts_db[0][0].upper()}{ts_db[0][1]}" if ts_db else None
                    vt_full = f"{phys_table}{vt_suffix}" if phys_table and vt_suffix else vt_suffix

                    # Extract nested columns list inside ts_node
                    cols: list[dict[str, Any]] = []
                    for sub in ts_node if isinstance(ts_node, list) else []:
                        if (
                            isinstance(sub, list)
                            and len(sub) >= 2
                            and isinstance(sub[0], str)
                            and UUID_RE.fullmatch(sub[0])
                        ):
                            for col_node in sub[2:]:
                                col_item = _extract_attr_entry(
                                    col_node, db_names, tmap, "КолонкаТЧ", parent_ts=ts_name
                                )
                                if col_item and col_item["uuid"] not in seen_sub:
                                    seen_sub.add(col_item["uuid"])
                                    col_item["physical_table"] = vt_full
                                    cols.append(col_item)
                                    attributes.append(col_item)

                    tabular_sections.append(
                        {
                            "name": ts_name,
                            "synonym": ts_syn,
                            "description": ts_desc,
                            "uuid": ts_uid,
                            "physical_suffix": vt_suffix,
                            "physical_table": vt_full,
                            "columns": cols,
                        }
                    )
                continue

            if sec_kind == "Значение перечисления" or item["class_name"] == "Перечисления":
                for ev_node in items_nodes:
                    hdr = _find_ident_header(ev_node)
                    if hdr and hdr[0] not in seen_sub and hdr[0] != uid:
                        seen_sub.add(hdr[0])
                        enum_values.append(
                            {"uuid": hdr[0], "name": hdr[1], "synonym": hdr[2], "description": hdr[3]}
                        )
                continue

            for attr_node in items_nodes:
                if isinstance(attr_node, str) and UUID_RE.fullmatch(attr_node):
                    child_uuids_typed.append((attr_node.lower(), sec_kind))
                    continue
                entry = _extract_attr_entry(attr_node, db_names, tmap, sec_kind)
                if entry and entry["uuid"] not in seen_sub and entry["uuid"] != uid:
                    seen_sub.add(entry["uuid"])
                    attributes.append(entry)

    # Regex fallback if tree parser didn't find anything on malformed/custom node
    if not attributes and not enum_values:
        sub_names = re.findall(
            r'\{1,0,([0-9a-f-]{36})\}\s*,\s*"([^"]+)"\s*,\s*\{\s*1\s*,\s*"ru"\s*,\s*"((?:[^"]|"")*)"',
            text,
            re.I,
        )
        for suid, sname, ssyn in sub_names:
            sl = suid.lower()
            if sl == uid or sl in seen_sub:
                continue
            seen_sub.add(sl)
            f_entries = db_names.get(sl, [])
            phys_col = f"_{f_entries[0][0].upper()}{f_entries[0][1]}" if f_entries else None
            attributes.append(
                {
                    "name": sname,
                    "synonym": ssyn.replace('""', '"'),
                    "description": "",
                    "uuid": sl,
                    "kind": "Реквизит",
                    "type": "",
                    "types": [],
                    "numeric": None,
                    "physical_col": phys_col,
                    "parent_ts": None,
                }
            )

    # Backward-compatible flat sub_elements list (including VT table entries for db mapping)
    sub_elements: list[dict[str, Any]] = []
    for a in attributes:
        sub_elements.append(
            {
                "name": f"{a['parent_ts']}.{a['name']}" if a["parent_ts"] else a["name"],
                "raw_name": a["name"],
                "synonym": a["synonym"],
                "uuid": a["uuid"],
                "kind": a["kind"],
                "type": a["type"],
                "numeric": a["numeric"],
                "physical_col": a["physical_col"],
                "parent_ts": a["parent_ts"],
            }
        )
    for ts in tabular_sections:
        sub_elements.append(
            {
                "name": ts["name"],
                "raw_name": ts["name"],
                "synonym": ts["synonym"],
                "uuid": ts["uuid"],
                "kind": "Табличная часть",
                "type": f"Таблица ({len(ts['columns'])} кол.)",
                "numeric": None,
                "physical_col": ts["physical_suffix"],
                "physical_table": ts["physical_table"],
                "parent_ts": None,
            }
        )

    # RegisterRecords (Движения документов) & BasedOn (Ввод на основании) via MetadataObjectID reference
    register_records: list[dict[str, str]] = []
    based_on: list[dict[str, str]] = []
    seen_reg: set[str] = set()
    for reg_uid in re.findall(
        rf'\{{"#"\s*,\s*{METADATA_REF_UUID}\s*,\s*\{{1\s*,\s*([0-9a-f-]{{36}})\}}\s*\}}',
        text,
        re.I | re.S,
    ):
        ru = reg_uid.lower()
        if ru not in seen_reg and ru != "00000000-0000-0000-0000-000000000000":
            seen_reg.add(ru)
            rlabel = tmap.get(ru, ru)
            if rlabel.startswith("Регистры "):
                register_records.append({"uuid": ru, "label": rlabel})
            else:
                based_on.append({"uuid": ru, "label": rlabel})

    # Child objects (Forms, Commands, Templates) — exclude top-level objects referenced in metadata
    # (such as RegisterRecords on Documents or CommonAttribute scope references)
    children: list[dict[str, str]] = []
    role_by_cu: dict[str, str] = {}
    for cu, sk in child_uuids_typed:
        if cu not in role_by_cu or role_by_cu[cu] == "Элемент":
            role_by_cu[cu] = sk
    for cu in sorted({u.lower() for u in UUID_RE.findall(text)} - {uid}):
        if cu in tmap and cu not in role_by_cu:
            # Skip cross-referenced top-level metadata objects unless explicitly in Forms/Commands/Templates
            continue
        if src.exists(cu):
            ctext = src.read_text(cu) or ""
            cname, csyn = extract_object_name(ctext)
            if cname:
                children.append(
                    {
                        "name": cname,
                        "synonym": csyn,
                        "uuid": cu,
                        "kind": role_by_cu.get(cu, "Подчиненный объект"),
                    }
                )

    # Extract useful scalar properties from header block
    props = _extract_class_properties(item["class_name"], tree, tmap)

    return {
        "object": item,
        "description": extract_object_comment(text[:1500]),
        "physical_table": phys_table,
        "physical_tables": all_phys_tables,
        "properties": props,
        "attributes": attributes,
        "tabular_sections": tabular_sections,
        "enum_values": enum_values,
        "register_records": register_records,
        "based_on": based_on,
        "sub_elements": sub_elements,
        "child_objects": children,
    }


def _looks_like_tabular_section(node: Any) -> bool:
    if not isinstance(node, list):
        return False
    for el in node:
        if isinstance(el, list) and len(el) >= 2 and isinstance(el[0], str) and UUID_RE.fullmatch(el[0]):
            # Nested section inside sub-item => tabular section columns
            return True
    return False


def _extract_class_properties(class_name: str, tree: Any, type_map: dict[str, str]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    if not isinstance(tree, list) or len(tree) < 2 or not isinstance(tree[1], list):
        return props
    hdr = tree[1]
    # Value / attribute Pattern for Constants
    if class_name == "Константы" or class_name == "Общие реквизиты":
        pat = _find_first_pattern(tree)
        if pat:
            props["type"] = decode_pattern(pat, type_map)["summary"]
    # Register periodicity / kind hints
    if class_name == "Регистры накопления":
        # hdr contains kind flag (0=Остатки, 1=Обороты) in standard layout
        text_flags = [x for x in hdr if isinstance(x, str) and x.isdigit()]
        if text_flags:
            props["header_flags_hint"] = text_flags[:12]
    return props


def load_subsystems_tree(src: ConfigSource, items: list[dict[str, str]]) -> dict[str, Any]:
    """Recursively extracts the full subsystem hierarchy and detects unassigned business objects."""
    by_uuid = {i["uuid"]: i for i in items}
    top_subsystems = [i for i in items if i["class_name"] == "Подсистемы"]
    visited: set[str] = set()
    assigned_uuids: set[str] = set()

    def _parse_sub(uid: str, fallback_name: str = "", fallback_syn: str = "") -> dict[str, Any] | None:
        if uid in visited:
            return None
        visited.add(uid)
        txt = src.read_text(uid) or ""
        name, syn = extract_object_name(txt)
        name = name or fallback_name or uid
        syn = syn or fallback_syn
        desc = extract_object_comment(txt[:1500])

        included: list[dict[str, str]] = []
        children: list[dict[str, Any]] = []
        seen_inc: set[str] = set()

        for u in UUID_RE.findall(txt):
            ul = u.lower()
            if ul == uid or ul == "00000000-0000-0000-0000-000000000000":
                continue
            if ul in by_uuid:
                obj = by_uuid[ul]
                if obj["class_name"] == "Подсистемы":
                    sub_node = _parse_sub(ul, obj["name"], obj["synonym"])
                    if sub_node:
                        children.append(sub_node)
                elif obj["class_name"] != "Общие картинки" and ul not in seen_inc:
                    seen_inc.add(ul)
                    assigned_uuids.add(ul)
                    included.append(
                        {
                            "uuid": ul,
                            "class_name": obj["class_name"],
                            "name": obj["name"],
                            "synonym": obj["synonym"],
                        }
                    )
            elif src.exists(ul) and ul not in visited:
                # Check if ul is a nested subsystem file
                sub_txt = src.read_text(ul) or ""
                if "37f2fa9a-b276-11d4-9435-004095e12fc7" in sub_txt.lower() or (
                    f"{{1,0,{ul}}}" in sub_txt.lower() and _looks_like_subsystem(sub_txt)
                ):
                    sub_node = _parse_sub(ul)
                    if sub_node:
                        children.append(sub_node)

        return {
            "uuid": uid,
            "name": name,
            "synonym": syn,
            "description": desc,
            "objects": included,
            "children": children,
        }

    roots: list[dict[str, Any]] = []
    for sub in top_subsystems:
        node = _parse_sub(sub["uuid"], sub["name"], sub["synonym"])
        if node:
            roots.append(node)

    unassigned = [
        i for i in items
        if i["class_name"] not in NON_BUSINESS_CLASSES and i["uuid"] not in assigned_uuids
    ]

    return {
        "subsystems": roots,
        "assigned_count": len(assigned_uuids),
        "unassigned_business_objects": unassigned,
    }


def _looks_like_subsystem(text: str) -> bool:
    """Heuristic check for nested subsystem serialization files."""
    if not text or not text.lstrip().startswith("{1,"):
        return False
    return bool(re.search(r'\{1,0,[0-9a-f-]{36}\}\s*,\s*"[^"]+"', text[:1000], re.I)) and (
        "{" in text[:200]
    )


def extract_v8_quoted_bsl(text: str) -> str | None:
    """Extracts 1C escaped BSL string embedded inside managed form '{4,{...},"...",0}'."""
    n = len(text)
    i = 0
    while i < n:
        if text[i] == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                ch = text[i]
                if ch == '"':
                    if i + 1 < n and text[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    break
                buf.append(ch)
                i += 1
            candidate = "".join(buf)
            if any(kw in candidate for kw in BSL_KEYWORDS) or len(candidate) > 80:
                return candidate
        i += 1
    return None


def read_bsl_from_file(src: ConfigSource, fname: str) -> str | None:
    """Reads BSL code from either an embedded container (.0/.2) or a managed form text file."""
    data = src.read_bytes(fname)
    if not data:
        return None
    if data.startswith(CONTAINER_MAGIC):
        cr = onec_dtools.ContainerReader(io.BytesIO(data))
        for entry_name in ("text", "module"):
            if entry_name in cr.entries:
                raw_entry = b"".join(cr.entries[entry_name].data)
                return decode_text(decompress_1c(raw_entry))
        return None
    text = decode_text(data)
    if text.lstrip().startswith(("{4,", "{3,")):
        return extract_v8_quoted_bsl(text)
    return None


def collect_object_modules(
    src: ConfigSource,
    obj_uuid: str,
    obj_name: str,
    obj_class: str = "",
    top_level_uuids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Collects all BSL modules directly on the object and on its owned forms/commands."""
    suffix_labels = {
        "0": "МодульОбъекта / ОбщийМодуль",
        "1": "МодульНабораЗаписей",
        "2": "МодульМенеджера / Команды",
        "3": "МодульВнешнегоСоединения",
        "6": "МодульПриложения",
        "7": "МодульСеанса",
    }
    results: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    all_files = src.list_files()
    files_by_base: dict[str, list[str]] = {}
    for fn in all_files:
        if "." in fn:
            base = fn.split(".", 1)[0].lower()
            files_by_base.setdefault(base, []).append(fn)

    for fn in files_by_base.get(obj_uuid, []):
        suf = fn.split(".", 1)[1]
        code = read_bsl_from_file(src, fn)
        if code and code.strip():
            seen_files.add(fn)
            kind = suffix_labels.get(suf, suf)
            results.append(
                {
                    "title": f"{obj_name}.{kind} [{fn}]",
                    "filename": fn,
                    "owner_name": obj_name,
                    "owner_class": obj_class,
                    "owner_uuid": obj_uuid,
                    "module_kind": kind,
                    "code": code,
                    "lines": len(code.splitlines()),
                }
            )

    if obj_class in (
        "Конфигурация",
        "Подсистемы",
        "Роли",
        "Журналы документов",
        "Общие реквизиты",
        "Функциональные опции",
        "Критерии отбора",
    ):
        return results

    skip_top = top_level_uuids or set()
    obj_text = src.read_text(obj_uuid) or ""
    child_uuids = {u.lower() for u in UUID_RE.findall(obj_text)} - {obj_uuid} - skip_top
    for cu in sorted(child_uuids):
        if cu not in files_by_base:
            continue
        ctext = src.read_text(cu)
        cname, _ = extract_object_name(ctext or "")
        label_prefix = cname or cu
        for fn in files_by_base[cu]:
            if fn in seen_files:
                continue
            code = read_bsl_from_file(src, fn)
            if code and code.strip():
                seen_files.add(fn)
                results.append(
                    {
                        "title": f"{obj_name}.{label_prefix} [{fn}]",
                        "filename": fn,
                        "owner_name": obj_name,
                        "owner_class": obj_class,
                        "owner_uuid": obj_uuid,
                        "module_kind": f"Форма/Команда ({label_prefix})",
                        "code": code,
                        "lines": len(code.splitlines()),
                    }
                )
    return results


def collect_all_modules(
    src: ConfigSource, cfg: dict[str, str], items: list[dict[str, str]], class_filter: str | None = None
) -> list[dict[str, Any]]:
    """Collects all BSL modules across configuration root, metadata objects, forms, and stray files."""
    all_mods: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    top_level_uuids = {i["uuid"] for i in items} | {cfg["uuid"]}

    if not class_filter or "конфигурац" in class_filter.lower():
        for m in collect_object_modules(
            src, cfg["uuid"], cfg["name"] or "Конфигурация", "Конфигурация", top_level_uuids
        ):
            seen_files.add(m["filename"])
            all_mods.append(m)

    for it in items:
        if it["class_name"] == "Общие картинки":
            continue
        if class_filter and class_filter.lower() not in it["class_name"].lower():
            continue
        for m in collect_object_modules(
            src, it["uuid"], it["name"], it["class_name"], top_level_uuids
        ):
            if m["filename"] not in seen_files:
                seen_files.add(m["filename"])
                all_mods.append(m)

    # Catch any remaining BSL files not linked via root items
    if not class_filter:
        image_uuids = {i["uuid"] for i in items if i["class_name"] == "Общие картинки"}
        for fn in src.list_files():
            if fn in seen_files or "." not in fn:
                continue
            base = fn.split(".", 1)[0].lower()
            if base in image_uuids:
                continue
            code = read_bsl_from_file(src, fn)
            if code and code.strip():
                seen_files.add(fn)
                all_mods.append(
                    {
                        "title": f"ПрочийМодуль [{fn}]",
                        "filename": fn,
                        "owner_name": base,
                        "owner_class": "Прочее",
                        "owner_uuid": base,
                        "module_kind": "ПрочийМодуль",
                        "code": code,
                        "lines": len(code.splitlines()),
                    }
                )
    return all_mods


def parse_dcs_schemas(
    src: ConfigSource, items: list[dict[str, str]], target_query: str | None = None
) -> list[dict[str, Any]]:
    """Extracts and parses DataCompositionSchema XML from Reports and DataProcessors."""
    candidates = (
        find_matching_objects(items, target_query)
        if target_query
        else [i for i in items if i["class_name"] in ("Отчеты", "Обработки", "Внешний объект (.epf/.ert)")]
    )
    all_files = src.list_files()
    files_by_base: dict[str, list[str]] = {}
    for fn in all_files:
        base = fn.split(".", 1)[0].lower()
        files_by_base.setdefault(base, []).append(fn)

    schemas: list[dict[str, Any]] = []
    for obj in candidates:
        uid = obj["uuid"]
        meta_text = src.read_text(uid) or ""
        child_uuids = {u.lower() for u in UUID_RE.findall(meta_text)} - {uid}
        scan_bases = [uid] + sorted(child_uuids)
        for base in scan_bases:
            for fn in files_by_base.get(base, []):
                if fn == uid:
                    continue
                xml_texts: list[tuple[str, str]] = []
                data = src.read_bytes(fn)
                if not data:
                    continue
                if data.startswith(CONTAINER_MAGIC):
                    cr = onec_dtools.ContainerReader(io.BytesIO(data))
                    for ek, eobj in cr.entries.items():
                        ed = decode_text(decompress_1c(b"".join(eobj.data)))
                        if "<dataCompositionSchema" in ed:
                            xml_texts.append((f"{fn}/{ek}", ed))
                else:
                    txt = decode_text(data)
                    if "<dataCompositionSchema" in txt:
                        xml_texts.append((fn, txt))

                ctext = src.read_text(base) or ""
                tpl_name, _ = extract_object_name(ctext) if base != uid else (obj["name"], obj["synonym"])
                for loc, xml_str in xml_texts:
                    parsed = _parse_dcs_xml(xml_str)
                    parsed["object_name"] = obj["name"]
                    parsed["object_class"] = obj["class_name"]
                    parsed["template_name"] = tpl_name or base
                    parsed["file"] = loc
                    parsed["xml"] = xml_str
                    schemas.append(parsed)
    return schemas


def _local_tag(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_dcs_xml(xml_str: str) -> dict[str, Any]:
    """Parses DCS XML into datasets, queries, parameters, calculated fields, totals, settings."""
    # Strip any trailing binary/garbage outside closing tag
    start = xml_str.find("<dataCompositionSchema")
    end = xml_str.rfind("</dataCompositionSchema>")
    clean_xml = xml_str[start : end + len("</dataCompositionSchema>")] if start >= 0 and end > start else xml_str

    result: dict[str, Any] = {
        "datasets": [],
        "total_fields": [],
        "calculated_fields": [],
        "parameters": [],
        "selection_fields": [],
        "parse_error": None,
    }
    root = None
    try:
        root = ET.fromstring(clean_xml)
    except ET.ParseError:
        # Retry after stripping unbound namespace prefixes commonly omitted in 1C DCS fragments
        stripped = re.sub(r'\s+[A-Za-z0-9_]+:[A-Za-z0-9_]+="[^"]*"', "", clean_xml)
        stripped = re.sub(r"<(/?)[A-Za-z0-9_]+:", r"<\1", stripped)
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as exc:
            result["parse_error"] = str(exc)
            queries = re.findall(r"<query>(.*?)</query>", clean_xml, re.S)
            for idx, q in enumerate(queries, 1):
                result["datasets"].append(
                    {"name": f"НаборДанных{idx}", "query": html.unescape(q.strip()), "fields": []}
                )
            return result

    for child in root:
        ltag = _local_tag(child.tag)
        if ltag == "dataSet":
            ds_name = ""
            ds_query = ""
            ds_fields = []
            for sub in child:
                st = _local_tag(sub.tag)
                if st == "name" and sub.text:
                    ds_name = sub.text.strip()
                elif st == "query" and sub.text:
                    ds_query = sub.text.strip()
                elif st == "field":
                    fname = ""
                    dpath = ""
                    for fsub in sub:
                        ft = _local_tag(fsub.tag)
                        if ft == "dataPath" and fsub.text:
                            dpath = fsub.text.strip()
                        elif ft == "field" and fsub.text:
                            fname = fsub.text.strip()
                    if fname or dpath:
                        ds_fields.append(fname or dpath)
            result["datasets"].append({"name": ds_name, "query": ds_query, "fields": ds_fields})
        elif ltag == "totalField":
            dpath = ""
            expr = ""
            for sub in child:
                st = _local_tag(sub.tag)
                if st == "dataPath" and sub.text:
                    dpath = sub.text.strip()
                elif st == "expression" and sub.text:
                    expr = sub.text.strip()
            result["total_fields"].append({"data_path": dpath, "expression": expr})
        elif ltag == "calculatedField":
            dpath = ""
            expr = ""
            for sub in child:
                st = _local_tag(sub.tag)
                if st == "dataPath" and sub.text:
                    dpath = sub.text.strip()
                elif st == "expression" and sub.text:
                    expr = sub.text.strip()
            result["calculated_fields"].append({"data_path": dpath, "expression": expr})
        elif ltag == "parameter":
            pname = ""
            use_restrict = ""
            for sub in child:
                st = _local_tag(sub.tag)
                if st == "name" and sub.text:
                    pname = sub.text.strip()
                elif st == "useRestriction" and sub.text:
                    use_restrict = sub.text.strip()
            result["parameters"].append({"name": pname, "use_restriction": use_restrict})
        elif ltag == "settingsVariant":
            for node in child.iter():
                if _local_tag(node.tag) == "field" and node.text and node.text.strip():
                    f = node.text.strip()
                    if f not in result["selection_fields"]:
                        result["selection_fields"].append(f)
    return result


def parse_forms(
    src: ConfigSource, items: list[dict[str, str]], target_query: str | None = None
) -> list[dict[str, Any]]:
    """Parses managed and ordinary forms: BSL procedures, commands, events, and dead handlers."""
    candidates = find_matching_objects(items, target_query) if target_query else items
    all_files = src.list_files()
    files_by_base: dict[str, list[str]] = {}
    for fn in all_files:
        base = fn.split(".", 1)[0].lower()
        files_by_base.setdefault(base, []).append(fn)

    forms_out: list[dict[str, Any]] = []
    seen_form_files: set[str] = set()

    for obj in candidates:
        if obj["class_name"] == "Общие картинки":
            continue
        uid = obj["uuid"]
        if obj["class_name"] == "Общие формы":
            form_bases = [(uid, obj["name"], obj["synonym"])]
        else:
            meta_txt = src.read_text(uid) or ""
            child_uuids = sorted({u.lower() for u in UUID_RE.findall(meta_txt)} - {uid})
            form_bases = []
            for cu in child_uuids:
                if f"{cu}.0" in all_files or any(f.startswith(cu + ".") for f in all_files):
                    ctext = src.read_text(cu) or ""
                    cname, csyn = extract_object_name(ctext)
                    form_bases.append((cu, cname or cu, csyn))

        for fuid, fname, fsyn in form_bases:
            for fn in files_by_base.get(fuid, []):
                if fn in seen_form_files:
                    continue
                data = src.read_bytes(fn)
                if not data:
                    continue
                code = read_bsl_from_file(src, fn)
                raw_text = ""
                if data.startswith(CONTAINER_MAGIC):
                    cr = onec_dtools.ContainerReader(io.BytesIO(data))
                    if "form" in cr.entries:
                        raw_text = decode_text(decompress_1c(b"".join(cr.entries["form"].data)))
                    elif "text" not in cr.entries and "module" not in cr.entries:
                        continue
                    form_kind = "Обычная форма"
                else:
                    raw_text = decode_text(data)
                    if not raw_text.lstrip().startswith(("{4,", "{3,")):
                        continue
                    form_kind = "Управляемая форма"

                seen_form_files.add(fn)
                procs = PROC_DEF_RE.findall(code or "")
                procs_lower = {p.lower() for p in procs}
                handlers, missing = _extract_form_handlers(raw_text, code or "", procs_lower)
                forms_out.append(
                    {
                        "owner_class": obj["class_name"],
                        "owner_name": obj["name"],
                        "form_name": fname,
                        "form_synonym": fsyn,
                        "form_uuid": fuid,
                        "file": fn,
                        "form_kind": form_kind,
                        "procedures": procs,
                        "bound_handlers": handlers,
                        "missing_handlers": missing,
                        "module_lines": len((code or "").splitlines()),
                    }
                )
    return forms_out


def _extract_form_handlers(
    raw_text: str, bsl_code: str, procs_lower: set[str]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Extracts event->handler pairs from managed form metadata and detects missing BSL procs."""
    # Remove the large BSL code block itself before scanning form metadata strings
    meta_part = raw_text
    if bsl_code:
        escaped = bsl_code.replace('"', '""')
        pos = meta_part.find(escaped[: min(80, len(escaped))])
        if pos >= 0:
            meta_part = meta_part[:pos] + meta_part[pos + len(escaped) :]

    # Standard 1C managed form event bindings appear as {"EventName","HandlerProc"} or {..., "OnCreateAtServer", "ПриСозданииНаСервере"}
    known_event_names = {
        "OnCreateAtServer", "OnOpen", "BeforeClose", "OnClose", "BeforeWrite", "BeforeWriteAtServer",
        "AfterWrite", "AfterWriteAtServer", "OnReadAtServer", "OnWriteAtServer", "FillCheckProcessingAtServer",
        "ChoiceProcessing", "NotificationProcessing", "URLProcessing",
        "OnChange", "StartChoice", "Clearing", "AutoComplete", "TextEditEnd",
        "OnActivateRow", "Selection", "BeforeAddRow", "AfterDeleteRow", "BeforeDeleteRow",
        "OnEditEnd", "OnStartEdit", "DragStart", "Drag", "DragCheck",
        "ПриСозданииНаСервере", "ПриОткрытии", "ПередЗакрытием", "ПриЗакрытии",
        "ПередЗаписью", "ПередЗаписьюНаСервере", "ПослеЗаписи", "ПослеЗаписиНаСервере",
        "ПриЧтенииНаСервере", "ПриЗаписиНаСервере", "ПриАктивизацииСтроки",
        "ПриИзменении", "НачалоВыбора", "Очистка", "Выбор", "ОбработкаВыбора",
        "ОбработкаОповещения", "ПередНачаломДобавления", "ПередУдалением", "ПослеУдаления",
    }
    handlers: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # Scan pairs like {"EventName","ProcName"}
    for ev, proc in re.findall(r'\{(?:\d+,)*"([A-Za-zА-Яа-яЁё0-9_]+)"\s*,\s*"([A-Za-zА-Яа-яЁё0-9_]+)"\}', meta_part):
        if ev in known_event_names:
            key = (ev, proc)
            if key not in seen:
                seen.add(key)
                rec = {"event": ev, "handler": proc}
                handlers.append(rec)
                if proc.lower() not in procs_lower:
                    missing.append(rec)
    return handlers, missing


def parse_roles(src: ConfigSource, cfg: dict[str, str], items: list[dict[str, str]]) -> dict[str, Any]:
    """Parses all Roles, resolves UUID object grants/restrictions, and detects byte-identical roles."""
    by_uuid = {i["uuid"]: i for i in items}
    role_items = [i for i in items if i["class_name"] == "Роли"]
    roles_out: list[dict[str, Any]] = []
    hashes: dict[str, list[str]] = {}

    for role in role_items:
        ruid = role["uuid"]
        rfile = f"{ruid}.0"
        raw_bytes = src.read_bytes(rfile)
        rt = decode_text(raw_bytes) if raw_bytes else ""
        rhash = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else ""
        if rhash:
            hashes.setdefault(rhash, []).append(role["name"])

        objects_grants: list[dict[str, Any]] = []
        if rt:
            for ou, rights_raw in re.findall(
                r"\{1,([0-9a-f-]{36}),[^}]*\}\s*,\s*\{0,(.*?)\}", rt, re.S | re.I
            ):
                oul = ou.lower()
                if oul == cfg["uuid"]:
                    oname = f"Конфигурация.{cfg['name']}"
                    oclass = "Конфигурация"
                elif oul in by_uuid:
                    oname = f"{by_uuid[oul]['class_name']}.{by_uuid[oul]['name']}"
                    oclass = by_uuid[oul]["class_name"]
                else:
                    oname = oul
                    oclass = "Неизвестный"
                pairs = re.findall(r"([0-9a-f-]{36}),(-?\d+)", rights_raw, re.I)
                granted = sum(1 for _, v in pairs if v == "1")
                denied = sum(1 for _, v in pairs if v == "-1")
                objects_grants.append(
                    {
                        "uuid": oul,
                        "object": oname,
                        "class_name": oclass,
                        "granted": granted,
                        "denied": denied,
                        "total_entries": len(pairs),
                    }
                )

        set_for_new = False
        if rt:
            # Parse trailing flags {..., {0}, {0}, 1, 1, 1, ...}
            rt_tree = parse_v8_tree(rt)
            if isinstance(rt_tree, list) and len(rt_tree) >= 4:
                set_for_new = any(x == "1" for x in rt_tree[3:6] if isinstance(x, str))

        roles_out.append(
            {
                "name": role["name"],
                "synonym": role["synonym"],
                "uuid": ruid,
                "rights_file": rfile if src.exists(rfile) else None,
                "sha256": rhash,
                "set_rights_for_new_objects": set_for_new,
                "objects_count": len(objects_grants),
                "objects": objects_grants,
            }
        )

    duplicate_groups = [names for names in hashes.values() if len(names) > 1]
    return {"roles": roles_out, "duplicate_groups": duplicate_groups}


def read_users_safe(src: ConfigSource) -> dict[str, Any]:
    """Safely inspects V8USERS from .1CD/.dt without touching password hashes (DATA redacted)."""
    if src.kind != "1cd":
        return {"supported": False, "reason": "Таблица V8USERS доступна только для .1CD и .dt.", "users": []}
    if "V8USERS" not in src.db.tables:
        return {"supported": False, "reason": "Таблица V8USERS отсутствует в базе.", "users": []}

    users: list[dict[str, Any]] = []
    for row in src.get_table_rows("V8USERS"):
        rec = {}
        for col, val in row.items():
            if col.upper() == "DATA":
                rec[col] = "<REDACTED>"
            else:
                rec[col] = format_cell(val)
        users.append(rec)
    return {"supported": True, "count": len(users), "users": users}


SYSTEM_MANIFEST_FILES = {"root", "versions", "version", "depot", "configinfo"}


def build_file_owner_map(
    src: ConfigSource, cfg: dict[str, str], items: list[dict[str, str]]
) -> dict[str, str]:
    """Maps any config filename or base UUID (including forms/commands/templates) to a readable owner label."""
    by_uuid = {i["uuid"]: i for i in items}
    owners: dict[str, str] = {}
    owners[cfg["uuid"]] = f"Конфигурация.{cfg['name']}"
    for it in items:
        owners[it["uuid"]] = f"{it['class_name']}.{it['name']}"
    for it in items:
        if it["class_name"] in ("Общие картинки", "Подсистемы", "Роли", "Журналы документов", "Общие реквизиты"):
            continue
        txt = src.read_text(it["uuid"]) or ""
        for u in UUID_RE.findall(txt):
            ul = u.lower()
            if ul not in by_uuid and ul != cfg["uuid"] and ul not in owners:
                cname = ""
                if src.exists(ul):
                    cname, _ = extract_object_name(src.read_text(ul) or "")
                owners[ul] = f"{it['class_name']}.{it['name']}.{cname}" if cname else f"{it['class_name']}.{it['name']}"
    return owners


def find_xrefs(
    src: ConfigSource,
    cfg: dict[str, str],
    items: list[dict[str, str]],
    target_query: str | None = None,
    unused_only: bool = False,
) -> dict[str, Any]:
    """Traces references to an object UUID/name or finds unreferenced metadata objects."""
    image_uuids = {i["uuid"] for i in items if i["class_name"] == "Общие картинки"}
    base_owners = build_file_owner_map(src, cfg, items)

    # Index text payloads of all non-image config files once (skip non-UUID system manifests for unused scans)
    searchable_files: list[tuple[str, str, str]] = []  # (filename, owner_label, text)
    for fn in src.list_files():
        base = fn.split(".", 1)[0].lower()
        if base in image_uuids:
            continue
        if fn.lower() in SYSTEM_MANIFEST_FILES or base in SYSTEM_MANIFEST_FILES:
            continue
        owner_prefix = base_owners.get(base)
        owner_lbl = f"{owner_prefix} [{fn}]" if owner_prefix else fn

        texts: list[str] = []
        raw_txt = src.read_text(fn)
        if raw_txt:
            texts.append(raw_txt)
        else:
            data = src.read_bytes(fn)
            if data and data.startswith(CONTAINER_MAGIC):
                cr = onec_dtools.ContainerReader(io.BytesIO(data))
                for ek, eobj in cr.entries.items():
                    ed = decode_text(decompress_1c(b"".join(eobj.data)))
                    if ed:
                        texts.append(ed)
        joined = "\n".join(texts)
        if joined:
            searchable_files.append((fn, owner_lbl, joined))

    if unused_only or not target_query:
        # Check which non-image/non-role/non-lang/non-style/non-subsystem objects have 0 external references.
        # Map every internal Type UUID back to the owning metadata item so attribute/DCS type references count!
        type_map = build_type_uuid_map(src, items)
        label_to_item_uid = {f"{i['class_name']}.{i['name']}": i["uuid"] for i in items}
        uuid_to_owner_item: dict[str, str] = {i["uuid"]: i["uuid"] for i in items}
        for tu, lbl in type_map.items():
            if lbl in label_to_item_uid:
                uuid_to_owner_item[tu] = label_to_item_uid[lbl]

        refs_by_uid: dict[str, set[str]] = {i["uuid"]: set() for i in items}
        for fn, owner_lbl, txt in searchable_files:
            base = fn.split(".", 1)[0].lower()
            if base == cfg["uuid"] or not UUID_RE.fullmatch(base):
                continue
            if base not in base_owners:
                continue
            txt_l = txt.lower()
            for uid in UUID_RE.findall(txt_l):
                target_item_uid = uuid_to_owner_item.get(uid)
                if target_item_uid and target_item_uid != base:
                    refs_by_uid[target_item_uid].add(owner_lbl)

        unused = []
        for it in items:
            if it["class_name"] in ("Общие картинки", "Языки", "Стили", "Роли", "Подсистемы"):
                continue
            uid = it["uuid"]
            ext_refs = sorted(refs_by_uid.get(uid, set()))
            # Also check BSL/text name references for objects typically invoked by name (CommonModules, CommonForms, etc.)
            if not ext_refs:
                name_hits = []
                pat = re.compile(rf"\b{re.escape(it['name'])}\b")
                for fn, owner_lbl, txt in searchable_files:
                    base = fn.split(".", 1)[0].lower()
                    if base in (uid, cfg["uuid"]):
                        continue
                    if pat.search(txt):
                        name_hits.append(owner_lbl)
                if not name_hits:
                    unused.append(it)
        return {"mode": "unused", "unused_objects": unused, "scanned_files": len(searchable_files)}

    # Specific target xref lookup
    matches = find_matching_objects(items, target_query)
    if not matches:
        # Allow searching raw UUID or keyword directly
        uid_q = target_query.strip().lower()
        hits = [
            owner_lbl for fn, owner_lbl, txt in searchable_files
            if uid_q in txt.lower()
        ]
        return {"mode": "query", "target": target_query, "uuid": uid_q, "references": hits}

    target = matches[0]
    tuid = target["uuid"]
    tname = target["name"]
    name_pat = re.compile(rf"\b{re.escape(tname)}\b")
    uuid_refs: list[str] = []
    name_refs: list[str] = []
    for fn, owner_lbl, txt in searchable_files:
        base = fn.split(".", 1)[0].lower()
        if base in (tuid, cfg["uuid"]):
            continue
        if tuid in txt.lower():
            uuid_refs.append(owner_lbl)
        elif name_pat.search(txt):
            name_refs.append(owner_lbl)

    return {
        "mode": "object",
        "target": target,
        "uuid_references": sorted(set(uuid_refs)),
        "name_references": sorted(set(name_refs)),
    }


def resolve_table_mappings(
    src: ConfigSource, items: list[dict[str, str]], type_map: dict[str, str] | None = None
) -> dict[str, Any]:
    """Builds complete physical_table -> colmap & human label maps (including Tabular Sections)."""
    tmap = type_map or build_type_uuid_map(src, items)
    table_to_colmap: dict[str, dict[str, str]] = {}
    table_to_label: dict[str, str] = {}
    lookup_index: dict[str, tuple[str, dict[str, str], str]] = {}  # lower query -> (phys_table, colmap, label)

    for it in items:
        if it["class_name"] == "Общие картинки":
            continue
        det = parse_object_details(src, it, tmap)
        pt = det.get("physical_table")
        base_label = f"{it['class_name']}.{it['name']}"
        cmap: dict[str, str] = {}
        for attr in det.get("attributes", []):
            pcol = attr.get("physical_col")
            if pcol and not attr.get("parent_ts"):
                cmap[pcol] = attr["name"]

        if pt:
            table_to_colmap[pt] = cmap
            table_to_label[pt] = base_label
            lookup_index[pt.lower()] = (pt, cmap, base_label)
            lookup_index[it["name"].lower()] = (pt, cmap, base_label)
            lookup_index[f"{it['class_name']}.{it['name']}".lower()] = (pt, cmap, base_label)

        for apt in det.get("physical_tables", []):
            table_to_label.setdefault(apt, base_label)
            table_to_colmap.setdefault(apt, cmap)

        for ts in det.get("tabular_sections", []):
            vtn = ts.get("physical_table")
            if not vtn:
                continue
            ts_cmap: dict[str, str] = {}
            for col in ts.get("columns", []):
                if col.get("physical_col"):
                    ts_cmap[col["physical_col"]] = col["name"]
            ts_label = f"{base_label}.{ts['name']}"
            table_to_colmap[vtn] = ts_cmap
            table_to_label[vtn] = ts_label
            lookup_index[vtn.lower()] = (vtn, ts_cmap, ts_label)
            lookup_index[f"{it['name']}.{ts['name']}".lower()] = (vtn, ts_cmap, ts_label)

    # Also label standard system tables
    system_labels = {
        "PARAMS": "Системная: Параметры ИБ",
        "CONFIG": "Системная: Конфигурация",
        "CONFIGSAVE": "Системная: Сохранённая конфигурация",
        "V8USERS": "Системная: Пользователи ИБ",
        "FILES": "Системная: Файлы",
        "IBVERSION": "Системная: Версия ИБ",
    }
    for k, v in system_labels.items():
        table_to_label.setdefault(k, v)

    return {
        "table_to_colmap": table_to_colmap,
        "table_to_label": table_to_label,
        "lookup_index": lookup_index,
    }

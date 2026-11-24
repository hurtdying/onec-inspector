---
name: inspect-1c
description: >-
  Universal inspection, metadata tree & subsystem analysis, BSL extraction,
  DCS (SKD) parsing, forms & roles audit, .1CD/.dt table reading, and container
  unpacking for ANY 1C:Enterprise 8 configuration (.dt, .1CD, .cf, .cfe, .epf,
  .ert, .efd) via ready-made scripts and MCP tools. Always activate when
  analyzing 1C files.
---

# Inspect 1C Files (`onec-inspector`)

> **STRICT POLICY:** Use **ONLY** the ready-made CLI commands in [onec_tool.py](./scripts/onec_tool.py) or the `onec-inspector` MCP server tools (`onec_summary`, `onec_subsystems`, `onec_object`, `onec_modules`, `onec_dcs`, `onec_forms`, `onec_roles`, `onec_users`, `onec_search`, `onec_xref`, `onec_tables`, `onec_rows`, `onec_audit`, `onec_raw`).
> **NEVER** write ad-hoc Python scripts (`scratch/*.py`, `inspect_*.py`, or inline `python -c` parsers) to inspect 1C metadata, BSL, DCS, roles, forms, or `.1CD` tables. All tools below are universal and work with **any** 1C configuration without hardcoded names or UUIDs.

For binary format notes, see [onec_dtools_api.md](./references/onec_dtools_api.md).

## Prerequisites

Verify `onec-dtools` is installed (`python -c "import onec_dtools" 2>$null || pip install onec-dtools`).

Set shortcut variable in PowerShell (point to `onec_tool.py` inside this skill folder):

```powershell
$SCRIPT = "<path-to-plugin>/skills/inspect-1c/scripts/onec_tool.py"
```

## Universal Analysis Workflow

For a full audit of any unfamiliar 1C configuration (`.dt`, `.1CD`, `.cf`, `.cfe`, `.epf`, `.ert`), run these ready-made commands sequentially instead of writing custom scripts:

### 1. Metadata Overview & Subsystem Tree

```powershell
python $SCRIPT summary "<path>" --subsystems
python $SCRIPT subsystems "<path>" --json
```

### 2. Automated Diagnostics (`audit`)

Runs configuration-agnostic checks across metadata, subsystems, unused objects (`xref`), BSL code (broken `Перечисления.*`, missing metadata refs, modals, `Execute`, queries in loops, empty `Except`), document `RegisterRecords` vs `ОбработкаПроведения`, broken form event handlers, numeric precision mismatches between documents/catalogs and registers, duplicate roles, safe `V8USERS` audit, and posted-doc vs register data consistency:

```powershell
python $SCRIPT audit "<path>"
python $SCRIPT audit "<path>" --json
```

### 3. Object Details (Attributes, Types, Tabular Sections, RegisterRecords, Enums)

```powershell
python $SCRIPT object "<path>" "<ObjectName_or_Class.Name_or_UUID>"
python $SCRIPT object "<path>" "<ObjectName>" --class "Справочники" --json
```

### 4. BSL Source Code Extraction (`module`)

```powershell
# List all BSL modules with line counts across entire config:
python $SCRIPT module "<path>" --list

# Extract one object (including its forms & commands) or root config modules:
python $SCRIPT module "<path>" "<ObjectName>"
python $SCRIPT module "<path>" "Конфигурация"

# Dump all BSL modules in the entire configuration to stdout or directory:
python $SCRIPT module "<path>" --all --out "<target_dir_or_file>"
```

### 5. DCS (СКД) Reports & Data Processors

Extracts datasets, SQL/1C `<query>` text, parameters, calculated fields, total fields, settings, or full cleaned XML:

```powershell
python $SCRIPT dcs "<path>" --all
python $SCRIPT dcs "<path>" "<ReportName>" --xml
```

### 6. Managed & Ordinary Forms

Inspects procedures, event-to-handler bindings, and detects missing form event procedures:

```powershell
python $SCRIPT forms "<path>" --all
python $SCRIPT forms "<path>" "<ObjectOrFormName>"
```

### 7. Roles, Rights & IB Users (Safe Mode)

```powershell
python $SCRIPT roles "<path>" --details
python $SCRIPT users "<path>"
```

### 8. Cross-References & Unused Objects (`xref`) and Text Search (`search`)

```powershell
python $SCRIPT xref "<path>" --unused
python $SCRIPT xref "<path>" "<ObjectName_or_UUID>"
python $SCRIPT search "<path>" "<Substring>" --modules-only -i
```

### 9. Physical `.1CD` / `.dt` Tables & Rows (`tables`, `rows`)

Counts exact non-empty rows AND slots in a single pass, resolves tabular sections (`Объект.ТабличнаяЧасть` / `_DOCUMENT*_VT*`), maps `_FLD*` columns to attribute names, and resolves `_IDRREF`/`*RREF` GUIDs to human-readable titles by default:

```powershell
python $SCRIPT tables "<path>" --non-empty
python $SCRIPT rows "<path>" "<ObjectName>" --limit 20
python $SCRIPT rows "<path>" "<ObjectName.TabularSection>" --limit 50
python $SCRIPT rows "<path>" "_DOCUMENT334_VT345" --where "<filter>" --raw-refs
```

### 10. Unpack / Repack / Raw

```powershell
python $SCRIPT unpack "<input.cf_or_epf_or_efd>" "<output_dir>"
python $SCRIPT build "<input_dir>" "<output.cf_or_epf>"
python $SCRIPT raw "<path>" "DBNames"
```

## Guardrails

- For `.1CD` bases with unsaved Designer edits, pass `--table CONFIGSAVE`.
- Pass `--force-reload` if `.dt` changed at the same path or you want to rebuild the cached `1Cv8.1CD`.
- Never run `1cv8t.exe DESIGNER /DumpConfigToFiles` (modal prompts can hang).
- Never extract or decrypt `V8USERS.DATA` hashes (`users` and `rows` always redact `DATA`).

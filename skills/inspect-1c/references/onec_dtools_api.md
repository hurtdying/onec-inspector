# onec_dtools API & 1C Internal Structures Reference

Based on [`infactum/onec_dtools`](https://github.com/infactum/onec_dtools).

## Core Python Classes and Functions

### `DatabaseReader` (`.1CD` databases, formats `8.2.14.0` and `8.3.8.0`)
```python
import onec_dtools

with open("1Cv8.1CD", "rb") as f:
    db = onec_dtools.DatabaseReader(f)
    # db.version, db.total_pages, db.page_size, db.locale
    # db.tables: OrderedDict[str, Table]
    for row in db.tables["CONFIG"]:
        if row.is_empty:
            continue
        # Lazy field conversion; avoid as_dict()/as_list() on wide tables unless needed
        fn = row["FILENAME"]
        blob = row["BINARYDATA"]  # Blob object; read via blob.value or iterate 256-byte chunks
```

Key notes:
- Always check `if row.is_empty: continue` before reading fields.
- `Blob`: `len(blob)` gives byte size; `blob.value` reads full `bytes` (for `I`) or UTF-16 `str` (for `NT`). Iterating `blob` yields 256-byte chunks for large BLOBs.
- System tables of primary interest:
  - `CONFIG` / `CONFIGSAVE`: configuration metadata, forms, modules (`FILENAME`, `PARTNO`, `BINARYDATA`).
  - `PARAMS`: `DBNames` (UUID-to-physical-table/field mapping), `users.usr`, `locale.inf`, `ibparams.inf`.
  - `DBSCHEMA`: `SERIALIZEDDATA` blob with physical table schemas.
  - `V8USERS`: infobase user accounts (`NAME`, `ADMROLE`, etc.).

### `ContainerReader` & `ContainerWriter` (`.cf`, `.cfe`, `.epf`, `.ert`, `.hbk`)
```python
import io
import onec_dtools

# Unpack/repack container files on disk:
onec_dtools.extract("sample.cf", "unpack_dir")
onec_dtools.build("unpack_dir", "repacked.cf")

# Or inspect entries in-memory without touching disk:
with open("sample.epf", "rb") as f:
    cr = onec_dtools.ContainerReader(f)
    for name, entry in cr.entries.items():
        # entry is File(name, size, created, modified, data_generator)
        raw = b"".join(entry.data)
```

### `SupplyReader` (`.efd` supply packages)
```python
import onec_dtools

with open("supply.efd", "rb") as f:
    sr = onec_dtools.SupplyReader(f)
    sr.unpack("output_dir")
```

## 1C Configuration Binary Layout Notes

1. **Multi-part files in `CONFIG` / `CONFIGSAVE`**:
   Large objects split across multiple rows with the same `FILENAME` and increasing `PARTNO`. Group by `FILENAME`, sort by `PARTNO`, concatenate `BINARYDATA.value`, then decompress with raw deflate `zlib.decompress(raw, -15)` (falling back to raw bytes if uncompressed).
2. **Configuration root resolution**:
   - `root` contains `{2,<root_uuid>,}` pointing to the main configuration file `<root_uuid>`.
   - `<root_uuid>` lists metadata class sections `{<class_uuid>,<count>,<item_uuid_1>,...}`.
3. **BSL modules inside `CONFIG` or `.cf`**:
   - **Object / Common / RecordSet / Manager / Command modules** (`<uuid>.0`, `<uuid>.1`, `<uuid>.2`, `<uuid>.3`): stored as nested 1C containers (magic `b"\xFF\xFF\xFF\x7F"`). Open with `ContainerReader(io.BytesIO(data))` and read entry `text` (or `module` for ordinary forms), decompressing with `zlib.decompress(..., -15)`.
   - **Managed Forms** (`<form_uuid>.0`): stored as UTF-8 bracketed text starting with `{4,`; the BSL form module sits as a `""`-escaped quoted string inside the structure.
4. **`.dt` files (`1CIBDmpF3`)**:
   `onec_dtools` does not directly parse `.dt` streams. Restore `.dt` into a temporary `1Cv8.1CD` via `1cv8.exe` / `1cv8t.exe` (`CREATEINFOBASE` + `DESIGNER /RestoreIB`), then inspect the `1Cv8.1CD` rapidly via `DatabaseReader`. Avoid `DESIGNER /DumpConfigToFiles` on `1cv8t.exe` (training platform), as it may hang waiting on modal prompts.

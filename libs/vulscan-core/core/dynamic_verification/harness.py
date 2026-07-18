"""Trusted real-call harness generators for dynamic verification.

No placeholder harness may claim target_reached / oracle success without an
actual call to the resolved target. TARGET_CALL_BEGIN is emitted immediately
before the real call.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

from core.dynamic_verification.oracle import HARNESS_SCHEMA_VERSION
from core.dynamic_verification.schema import normalize_language


def build_real_call_harness(
    plan: Dict[str, Any],
    *,
    language: str,
    test_id: str,
    unit_id: str,
    finding_id: str = "",
    attempt_id: str = "",
    target_module: str = "",
    target_qualname: str = "",
    target_symbol: str = "",
    package_name: str = "",
    source_basename: str = "",
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Build language-specific harness that actually invokes the target.

    Returns ({test_script, test_filename, dockerfile_bits, ...}, error).
    On failure to build a reliable adapter → error (caller must block).
    """
    lang = normalize_language(language)
    entry = str(plan.get("entrypoint") or (plan.get("invocation") or {}).get("command") or "")
    if not entry and not target_qualname and not target_symbol:
        return None, "missing_entrypoint"

    qualname = target_qualname or entry
    module = target_module
    symbol = target_symbol or qualname.split(".")[-1]

    if lang in ("python", "py"):
        return _python_adapter(
            plan,
            test_id=test_id,
            unit_id=unit_id,
            finding_id=finding_id,
            attempt_id=attempt_id,
            module=module or _python_module_from_unit(unit_id, source_basename),
            qualname=qualname,
        )
    if lang in ("javascript", "js", "typescript", "ts"):
        return _js_adapter(
            plan,
            test_id=test_id,
            unit_id=unit_id,
            finding_id=finding_id,
            attempt_id=attempt_id,
            module_file=source_basename or "target_code.js",
            export_path=qualname,
        )
    if lang in ("go", "golang"):
        if not symbol or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", symbol):
            return None, "go_symbol_unresolvable"
        return _go_adapter(
            plan,
            test_id=test_id,
            unit_id=unit_id,
            finding_id=finding_id,
            attempt_id=attempt_id,
            package_name=package_name or "main",
            symbol=symbol,
        )
    if lang in ("c", "cpp", "c++"):
        if not symbol or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", symbol):
            return None, "native_symbol_unresolvable"
        return _native_adapter(
            plan,
            test_id=test_id,
            unit_id=unit_id,
            finding_id=finding_id,
            attempt_id=attempt_id,
            symbol=symbol,
            source_basename=source_basename or "target_code.c",
            is_cpp=lang in ("cpp", "c++"),
        )
    return None, f"unsupported_language:{lang}"


def _python_module_from_unit(unit_id: str, source_basename: str) -> str:
    if source_basename.endswith(".py"):
        return source_basename[:-3].replace("/", ".").replace("\\", ".")
    # unit_id like path/mod.py:func
    left = (unit_id or "").split(":")[0]
    if left.endswith(".py"):
        return left[:-3].replace("/", ".").replace("\\", ".")
    return "target_code"


def _identity_payload(
    *,
    test_id: str,
    unit_id: str,
    finding_id: str,
    attempt_id: str,
    entry: str,
) -> dict:
    return {
        "test_id": test_id,
        "finding_id": finding_id,
        "unit_id": unit_id,
        "entrypoint": entry,
        "attempt_id": attempt_id,
    }


def _emit_begin_py(
    test_id: str, unit_id: str, entry: str, finding_id: str, attempt_id: str
) -> str:
    payload = json.dumps(
        _identity_payload(
            test_id=test_id,
            unit_id=unit_id,
            finding_id=finding_id,
            attempt_id=attempt_id,
            entry=entry,
        ),
        ensure_ascii=False,
    )
    return (
        f"print('TARGET_CALL_BEGIN ' + {json.dumps(payload)}, "
        f"file=sys.stderr, flush=True)"
    )


def _python_adapter(
    plan, *, test_id, unit_id, finding_id, attempt_id, module, qualname
) -> Tuple[Optional[dict], str]:
    if not module or not qualname:
        return None, "python_module_or_qualname_missing"
    # Reject path traversal in module name
    if ".." in module or module.startswith("/"):
        return None, "python_module_invalid"
    payload = plan.get("payload")
    parts = [p for p in qualname.split(".") if p]
    if not parts:
        return None, "python_qualname_empty"
    # If qualname includes module prefix, strip when matching imported module
    attr_path = parts
    if attr_path[0] == module.split(".")[-1] and len(attr_path) > 1:
        attr_path = attr_path[1:]

    body = f'''# Trusted harness — real Python call adapter (911VulScan)
import importlib, json, sys, traceback
TEST_ID = {json.dumps(test_id)}
FINDING_ID = {json.dumps(finding_id)}
UNIT_ID = {json.dumps(unit_id)}
ATTEMPT_ID = {json.dumps(attempt_id)}
MODULE = {json.dumps(module)}
ATTR_PATH = {json.dumps(attr_path)}
ENTRY = {json.dumps(qualname)}
PAYLOAD = {json.dumps(payload, default=str)}
SCHEMA = {json.dumps(HARNESS_SCHEMA_VERSION)}

def _resolve(mod, path):
    obj = mod
    for name in path:
        obj = getattr(obj, name)
    return obj

def _report(**kwargs):
    base = {{
        "schema_version": SCHEMA,
        "test_id": TEST_ID,
        "finding_id": FINDING_ID,
        "unit_id": UNIT_ID,
        "attempt_id": ATTEMPT_ID,
        "entrypoint": ENTRY,
        "call_begun": False,
        "call_completed": False,
        "return_repr": None,
        "exception_type": None,
        "exception_message": None,
        "observations": {{}},
    }}
    base.update(kwargs)
    print(json.dumps(base, ensure_ascii=False), flush=True)

def main():
    try:
        mod = importlib.import_module(MODULE)
    except Exception as exc:
        _report(observations={{"import_error": type(exc).__name__ + ":" + str(exc)}})
        return
    try:
        fn = _resolve(mod, ATTR_PATH)
    except Exception as exc:
        _report(observations={{"resolve_error": type(exc).__name__ + ":" + str(exc)}})
        return
    if not callable(fn):
        _report(observations={{"resolve_error": "not_callable"}})
        return
    {_emit_begin_py(test_id, unit_id, qualname, finding_id, attempt_id)}
    try:
        if isinstance(PAYLOAD, dict):
            result = fn(**PAYLOAD) if PAYLOAD else fn()
        elif isinstance(PAYLOAD, (list, tuple)):
            result = fn(*PAYLOAD)
        elif PAYLOAD is None:
            result = fn()
        else:
            result = fn(PAYLOAD)
        _report(
            call_begun=True,
            call_completed=True,
            return_repr=repr(result)[:2000],
            observations={{"called": True}},
        )
    except TypeError as exc:
        # Signature incompatible — do not fake success
        _report(
            call_begun=True,
            call_completed=False,
            exception_type="TypeError",
            exception_message=str(exc)[:1000],
            observations={{"signature_error": True}},
        )
    except Exception as exc:
        _report(
            call_begun=True,
            call_completed=False,
            exception_type=type(exc).__name__,
            exception_message=str(exc)[:1000],
            observations={{"raised": True}},
        )

if __name__ == "__main__":
    main()
'''
    return {
        "test_script": body,
        "test_filename": "vulscan_dynamic_test.py",
        "language": "python",
        "target_module": module,
        "target_qualname": qualname,
    }, ""


def _js_adapter(
    plan, *, test_id, unit_id, finding_id, attempt_id, module_file, export_path
) -> Tuple[Optional[dict], str]:
    if not module_file or not export_path:
        return None, "js_export_unresolvable"
    if ".." in module_file or module_file.startswith("/"):
        return None, "js_module_path_invalid"
    parts = [p for p in str(export_path).replace("/", ".").split(".") if p]
    # Drop filename-ish prefix
    if parts and parts[0] in (module_file, module_file.replace(".js", ""), "target_code"):
        parts = parts[1:] or parts
    payload = plan.get("payload")
    module_path = "./" + module_file.replace("\\", "/")
    body = f"""// Trusted harness — real JS/TS export call adapter (911VulScan)
const TEST_ID = {json.dumps(test_id)};
const FINDING_ID = {json.dumps(finding_id)};
const UNIT_ID = {json.dumps(unit_id)};
const ATTEMPT_ID = {json.dumps(attempt_id)};
const ENTRY = {json.dumps(export_path)};
const ATTR_PATH = {json.dumps(parts)};
const MODULE_FILE = {json.dumps(module_path)};
const PAYLOAD = {json.dumps(payload, default=str)};
const SCHEMA = {json.dumps(HARNESS_SCHEMA_VERSION)};

function report(extra) {{
  const base = {{
    schema_version: SCHEMA,
    test_id: TEST_ID,
    finding_id: FINDING_ID,
    unit_id: UNIT_ID,
    attempt_id: ATTEMPT_ID,
    entrypoint: ENTRY,
    call_begun: false,
    call_completed: false,
    return_repr: null,
    exception_type: null,
    exception_message: null,
    observations: {{}},
  }};
  Object.assign(base, extra);
  console.log(JSON.stringify(base));
}}

function resolve(obj, path) {{
  let cur = obj;
  for (const name of path) {{
    if (cur == null) throw new Error("missing:" + name);
    // default export bridge
    if (name === "default" && cur.default !== undefined) {{
      cur = cur.default;
      continue;
    }}
    cur = cur[name];
  }}
  return cur;
}}

let mod;
try {{
  mod = require(MODULE_FILE);
}} catch (e) {{
  report({{observations: {{import_error: String(e)}}}});
  process.exit(0);
}}

let fn;
try {{
  fn = ATTR_PATH.length ? resolve(mod, ATTR_PATH) : (mod.default || mod);
}} catch (e) {{
  report({{observations: {{resolve_error: String(e)}}}});
  process.exit(0);
}}

if (typeof fn !== "function") {{
  // Try module itself if it's a function export
  if (typeof mod === "function" && ATTR_PATH.length === 0) {{
    fn = mod;
  }} else {{
    report({{observations: {{resolve_error: "not_callable"}}}});
    process.exit(0);
  }}
}}

console.error("TARGET_CALL_BEGIN " + JSON.stringify({{
  test_id: TEST_ID, finding_id: FINDING_ID, unit_id: UNIT_ID,
  attempt_id: ATTEMPT_ID, entrypoint: ENTRY
}}));

try {{
  let result;
  if (PAYLOAD !== null && typeof PAYLOAD === "object" && !Array.isArray(PAYLOAD)) {{
    result = fn(PAYLOAD);
  }} else if (Array.isArray(PAYLOAD)) {{
    result = fn(...PAYLOAD);
  }} else if (PAYLOAD === null || PAYLOAD === undefined) {{
    result = fn();
  }} else {{
    result = fn(PAYLOAD);
  }}
  Promise.resolve(result).then((r) => {{
    report({{
      call_begun: true,
      call_completed: true,
      return_repr: String(r).slice(0, 2000),
      observations: {{called: true}},
    }});
  }}).catch((e) => {{
    report({{
      call_begun: true,
      call_completed: false,
      exception_type: e && e.name ? e.name : "Error",
      exception_message: String(e).slice(0, 1000),
      observations: {{raised: true}},
    }});
  }});
}} catch (e) {{
  report({{
    call_begun: true,
    call_completed: false,
    exception_type: e && e.name ? e.name : "Error",
    exception_message: String(e).slice(0, 1000),
    observations: {{raised: true}},
  }});
}}
"""
    return {
        "test_script": body,
        "test_filename": "vulscan_dynamic_test.js",
        "language": "javascript",
        "target_export": export_path,
        "module_file": module_file,
    }, ""


def _go_adapter(
    plan, *, test_id, unit_id, finding_id, attempt_id, package_name, symbol
) -> Tuple[Optional[dict], str]:
    # Generate a test file in the same package that calls the real symbol.
    pkg = package_name if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", package_name) else "main"
    body = f"""package {pkg}
// Trusted harness — real Go call adapter (911VulScan)
import (
  "encoding/json"
  "fmt"
  "os"
)

func main() {{
  testID := {json.dumps(test_id)}
  findingID := {json.dumps(finding_id)}
  unitID := {json.dumps(unit_id)}
  attemptID := {json.dumps(attempt_id)}
  entry := {json.dumps(symbol)}
  schema := {json.dumps(HARNESS_SCHEMA_VERSION)}
  report := func(begun, completed bool, ret, exType, exMsg string, obs map[string]any) {{
    out := map[string]any{{
      "schema_version": schema,
      "test_id": testID,
      "finding_id": findingID,
      "unit_id": unitID,
      "attempt_id": attemptID,
      "entrypoint": entry,
      "call_begun": begun,
      "call_completed": completed,
      "return_repr": ret,
      "exception_type": exType,
      "exception_message": exMsg,
      "observations": obs,
    }}
    b, _ := json.Marshal(out)
    fmt.Println(string(b))
  }}
  begin, _ := json.Marshal(map[string]string{{
    "test_id": testID, "finding_id": findingID, "unit_id": unitID,
    "attempt_id": attemptID, "entrypoint": entry,
  }})
  fmt.Fprintln(os.Stderr, "TARGET_CALL_BEGIN "+string(begin))
  {symbol}()
  report(true, true, "", "", "", map[string]any{{"called": true}})
}}
"""
    return {
        "test_script": body,
        "test_filename": "vulscan_dynamic_test.go",
        "language": "go",
        "package_name": pkg,
        "target_symbol": symbol,
    }, ""


def _is_safe_include_basename(name: str) -> bool:
    """True when *name* is safe to embed in a C ``#include "..."`` line.

    The basename comes from the scanned (untrusted) repository; a ``"``,
    ``\\``, newline, or control character would break out of the generated
    C string and inject arbitrary code into the harness source.
    """
    if any(ch in name for ch in ('"', "\\", "\n", "\r")):
        return False
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)


def _native_adapter(
    plan, *, test_id, unit_id, finding_id, attempt_id, symbol, source_basename, is_cpp: bool
) -> Tuple[Optional[dict], str]:
    if source_basename and not _is_safe_include_basename(source_basename):
        return None, "native_source_basename_invalid"
    include = source_basename if source_basename.endswith((".h", ".hpp")) else ""
    decl = f"extern int {symbol}(void);" if not is_cpp else f"extern \"C\" int {symbol}(void);"
    header_line = f'#include "{include}"\n' if include else ""
    body = f"""/* Trusted harness — real C/C++ call adapter (911VulScan) */
#include <stdio.h>
#include <stdlib.h>
{header_line}{decl}

int main(void) {{
  const char *test_id = {json.dumps(test_id)};
  const char *finding_id = {json.dumps(finding_id)};
  const char *unit_id = {json.dumps(unit_id)};
  const char *attempt_id = {json.dumps(attempt_id)};
  const char *entry = {json.dumps(symbol)};
  fprintf(stderr,
    "TARGET_CALL_BEGIN {{\\"test_id\\":\\"%s\\",\\"finding_id\\":\\"%s\\",\\"unit_id\\":\\"%s\\","
    "\\"attempt_id\\":\\"%s\\",\\"entrypoint\\":\\"%s\\"}}\\n",
    test_id, finding_id, unit_id, attempt_id, entry);
  int rc = {symbol}();
  printf("{{\\"schema_version\\":\\"%s\\",\\"test_id\\":\\"%s\\",\\"finding_id\\":\\"%s\\","
         "\\"unit_id\\":\\"%s\\",\\"attempt_id\\":\\"%s\\",\\"entrypoint\\":\\"%s\\","
         "\\"call_begun\\":true,\\"call_completed\\":true,"
         "\\"return_repr\\":\\"%d\\",\\"exception_type\\":null,\\"exception_message\\":null,"
         "\\"observations\\":{{\\"called\\":true}}}}\\n",
         {json.dumps(HARNESS_SCHEMA_VERSION)}, test_id, finding_id, unit_id, attempt_id, entry, rc);
  return 0;
}}
"""
    ext = "cpp" if is_cpp else "c"
    return {
        "test_script": body,
        "test_filename": f"vulscan_dynamic_test.{ext}",
        "language": "c++" if is_cpp else "c",
        "target_symbol": symbol,
        "link_sources": [source_basename] if source_basename else [],
    }, ""


def resolve_target_identity(
    *,
    unit_id: str,
    entrypoint: str,
    location: Optional[dict] = None,
    language: str = "",
) -> Dict[str, str]:
    """Derive module/qualname/symbol from canonical unit_id and plan entrypoint."""
    location = location or {}
    file_path = str(location.get("file") or (unit_id or "").split(":")[0] or "")
    func = str(location.get("function") or "")
    # unit_id often "file.py:Class.method" or "file.py:func"
    uid_func = ""
    if ":" in (unit_id or ""):
        uid_func = (unit_id or "").split(":", 1)[1]
    qualname = entrypoint or uid_func or func
    # Strip file prefix from function field if present
    if ":" in qualname:
        qualname = qualname.split(":", 1)[1]
    basename = os_basename(file_path)
    lang = normalize_language(language)
    module = ""
    if lang in ("python", "py") and basename.endswith(".py"):
        module = basename[:-3]
    symbol = qualname.split(".")[-1] if qualname else ""
    package = "main"
    return {
        "file_path": file_path,
        "source_basename": basename,
        "module": module,
        "qualname": qualname,
        "symbol": symbol,
        "package_name": package,
        "entrypoint": qualname,
    }


def os_basename(path: str) -> str:
    import os

    return os.path.basename(path.replace("\\", "/")) if path else ""

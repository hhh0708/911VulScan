"""Tests for native dynamic-test staging (headers, module companions)."""

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub


def _make_testbench_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "cwe-testbench"
    include = repo / "include"
    src = repo / "src"
    data = repo / "data"
    include.mkdir(parents=True)
    src.mkdir(parents=True)
    data.mkdir(parents=True)

    (include / "testbench.h").write_text(
        '#ifndef TB_H\n#define TB_H\nint tb_copy_username(const char *, char *, size_t);\n#endif\n'
    )
    (include / "net_service.h").write_text(
        '#ifndef NET_H\n#define NET_H\nint tb_http_route_request(const char *, const char *, const char *, const char *, size_t, char *, size_t);\n#endif\n'
    )
    (src / "buffer_overflow.c").write_text(
        '#include "testbench.h"\n#include <string.h>\n'
        'int tb_copy_username(const char *input, char *out, size_t out_size){ (void)out_size; strcpy(out,input); return 0; }\n'
    )
    (src / "command_injection.c").write_text(
        '#include "testbench.h"\nint tb_ping_host(const char *host){ (void)host; return 0; }\n'
    )
    (src / "http_handlers.c").write_text(
        '#include "net_service.h"\n#include "testbench.h"\n'
        'int tb_http_route_request(const char *m,const char *p,const char *q,const char *b,size_t bl,char *r,size_t rs){ (void)m;(void)p;(void)q;(void)b;(void)bl;(void)r;(void)rs; tb_copy_username("", r, rs); tb_ping_host(q); return 0; }\n'
    )
    (src / "main.c").write_text('#include "testbench.h"\nint main(void){return 0;}\n')
    (data / "sample.txt").write_text("hello\n")
    return repo


def test_enumerate_stage_artifacts_resolves_include_dir_headers(tmp_path):
    from utilities.dynamic_tester.native_stage import enumerate_stage_artifacts

    repo = _make_testbench_repo(tmp_path)
    source = repo / "src" / "buffer_overflow.c"

    basename, staged, paths = enumerate_stage_artifacts(str(source), str(repo))

    assert basename == "buffer_overflow.c"
    assert "testbench.h" in staged
    assert paths["testbench.h"].endswith(os.path.join("include", "testbench.h"))
    assert "command_injection.c" not in staged


def test_http_handlers_stages_module_companions(tmp_path):
    from utilities.dynamic_tester.native_stage import enumerate_stage_artifacts

    repo = _make_testbench_repo(tmp_path)
    source = repo / "src" / "http_handlers.c"

    _basename, staged, _paths = enumerate_stage_artifacts(str(source), str(repo))

    assert "testbench.h" in staged
    assert "net_service.h" in staged
    assert "buffer_overflow.c" in staged
    assert "command_injection.c" in staged
    assert "main.c" not in staged


def test_iniparser_stages_dictionary_companion(tmp_path):
    from utilities.dynamic_tester.native_stage import enumerate_stage_artifacts

    repo = tmp_path / "iniparser"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "dictionary.h").write_text(
        'struct _dictionary_;\ntypedef struct _dictionary_ dictionary;\n'
        'dictionary * dictionary_new(int size);\n'
    )
    (src / "dictionary.c").write_text(
        '#include "dictionary.h"\n'
        'dictionary * dictionary_new(int size){ (void)size; return 0; }\n'
    )
    (src / "iniparser.h").write_text('#include "dictionary.h"\n')
    (src / "iniparser.c").write_text(
        '#include "iniparser.h"\n'
        'void iniparser_freedict(dictionary * d){ dictionary_del(d); }\n'
    )

    basename, staged, paths = enumerate_stage_artifacts(str(src / "iniparser.c"), str(repo))

    assert basename == "iniparser.c"
    assert "dictionary.h" in staged
    assert "dictionary.c" in staged
    assert paths["dictionary.c"].endswith(os.path.join("src", "dictionary.c"))


def test_write_test_files_stages_include_headers(tmp_path):
    from utilities.dynamic_tester.docker_executor import _write_test_files
    from utilities.dynamic_tester.dockerfile_builder import validate_dockerfile

    repo = _make_testbench_repo(tmp_path)
    source = repo / "src" / "buffer_overflow.c"
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    generation = {
        "dockerfile": "FROM gcc:13\nWORKDIR /work\n",
        "test_script": '#include "testbench.h"\nint main(void){return 0;}\n',
        "test_filename": "test_exploit.c",
        "_language": "c",
    }

    out = _write_test_files(
        str(work_dir),
        generation,
        source_file=str(source),
        language="c",
        repo_path=str(repo),
    )

    assert (work_dir / "testbench.h").exists()
    assert (work_dir / "buffer_overflow.c").exists()
    dockerfile = (work_dir / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY testbench.h ." in dockerfile
    assert validate_dockerfile(dockerfile) == []
    assert "testbench.h" in out["dockerfile"]


def test_build_native_dockerfile_compiles_iniparser_bundle():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script='#include "iniparser.h"\n',
        staged_files=[
            "test_exploit.c",
            "iniparser.c",
            "iniparser.h",
            "dictionary.c",
            "dictionary.h",
        ],
        source_basename="iniparser.c",
    )
    dockerfile = build_native_dockerfile(ctx)

    compile_lines = [ln for ln in dockerfile.splitlines() if " -c " in ln]
    compiled = " ".join(compile_lines)
    assert "-c iniparser.c" in compiled
    assert "-c dictionary.c" in compiled


def test_build_native_dockerfile_compiles_module_bundle(tmp_path):
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script='extern int tb_http_route_request(const char *, const char *, const char *, const char *, size_t, char *, size_t);\n',
        staged_files=[
            "test_exploit.c",
            "http_handlers.c",
            "buffer_overflow.c",
            "command_injection.c",
            "testbench.h",
            "net_service.h",
        ],
        source_basename="http_handlers.c",
    )
    dockerfile = build_native_dockerfile(ctx)

    compile_lines = [ln for ln in dockerfile.splitlines() if " -c " in ln]
    compiled = " ".join(compile_lines)
    assert "-c http_handlers.c" in compiled
    assert "-c buffer_overflow.c" in compiled
    assert "-c command_injection.c" in compiled
    assert "-c main.c" not in compiled

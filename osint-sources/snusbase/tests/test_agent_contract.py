import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
AGENTS_PATH = ROOT / "AGENTS.md"
PYPROJECTS = [
    ROOT / "pyproject.toml",
    ROOT / "osint-sources" / "snusbase" / "pyproject.toml",
    ROOT / "osint-sources" / "dehashed" / "pyproject.toml",
]

_REQUIRES_PYTHON = re.compile(r'(?m)^requires-python\s*=\s*"([^"]+)"')


def _agents_text() -> str:
    assert AGENTS_PATH.is_file(), "AGENTS.md is missing"
    return AGENTS_PATH.read_text()


def test_agents_md_quotes_every_ci_run_step() -> None:
    run_lines = [line.strip() for line in CI_PATH.read_text().splitlines() if "run:" in line]
    assert run_lines, "ci.yml has no run: line"
    agents = _agents_text()
    for line in run_lines:
        assert line.startswith("- run:"), line
        command = line.removeprefix("- run:").strip()
        assert command
        assert command in agents


def test_agents_md_quotes_requires_python() -> None:
    agents = _agents_text()
    found = False
    for path in PYPROJECTS:
        match = _REQUIRES_PYTHON.search(path.read_text())
        assert match is not None, path
        assert match.group(1) in agents
        found = True
    assert found


def test_agents_md_points_at_the_source_docs() -> None:
    text = _agents_text()
    for path in (
        "docs/architecture.md",
        "docs/mcp-conventions.md",
        "docs/snusbase-contract.md",
        "docs/dehashed-contract.md",
        "docs/adding-a-source.md",
        "osint-sources/snusbase/README.md",
        "osint-sources/dehashed/README.md",
    ):
        assert path in text
        assert (ROOT / path).is_file()

"""Dotenv parsing used by `enclave exec` / `enclave run`."""

from enclave import dotenv


def test_basic_shapes():
    text = """
# comment
export A=1
B = two words
C='literal $HOME \\n'
D="line\\nbreak \\"q\\" back\\\\slash"
E=value # trailing comment
F="keep # this"
G=
H=a#b
"""
    entries, bad = dotenv.parse(text)
    assert bad == []
    assert entries == {
        "A": "1",
        "B": "two words",
        "C": "literal $HOME \\n",
        "D": 'line\nbreak "q" back\\slash',
        "E": "value",
        "F": "keep # this",
        "G": "",
        "H": "a#b",
    }


def test_reports_unparseable_lines():
    _, bad = dotenv.parse("OK=1\nnot a line\n=nokey\n")
    assert bad == [2, 3]


def test_merge_later_wins():
    assert dotenv.merge(["A=1\nB=1", "B=2\nC=3"]) == {"A": "1", "B": "2", "C": "3"}


def test_env_file_names():
    assert all(dotenv.is_env_file(n) for n in [".env", ".env.local", ".env.production", "prod.env"])
    assert not any(dotenv.is_env_file(n) for n in ["config.json", "envfile", ".envrc"])


def test_shell_quote_line_round_trips():
    for value in ["plain", "with space", "it's", 'multi\nline "x" \\', "", "a#b c"]:
        line = dotenv.shell_quote_line("K", value)
        assert dotenv.parse(line)[0] == {"K": value}, line

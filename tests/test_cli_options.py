import subprocess
import sys

import pytest

from passkey_bridge.cli import ssh_command


@pytest.mark.parametrize("executable", ["/path;id", "$(id)", "~/bin/a b", "-bad", "'evil'"])
def test_remote_executable_rejects_shell_injection(executable):
    with pytest.raises(ValueError):
        ssh_command("host", 1234, executable)


def test_custom_remote_install_location():
    assert ssh_command("host", 1234, "/usr/local/bin/passkey-bridge")[-1] == "/usr/local/bin/passkey-bridge relay --port 1234"


def test_optional_code_and_custom_executable_are_documented_in_cli_help():
    result = subprocess.run([sys.executable, "-m", "passkey_bridge.cli", "connect", "--help"],
                            text=True, capture_output=True, check=True)
    assert "--code" in result.stdout
    assert "--remote-executable" in result.stdout

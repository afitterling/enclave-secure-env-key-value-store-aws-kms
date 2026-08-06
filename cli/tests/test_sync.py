"""Guards on pull: server-supplied filenames must not escape --dest."""

import pytest

from enclave import sync


@pytest.mark.parametrize(
    "name",
    ["../../.ssh/authorized_keys", "/etc/passwd", "a/b", "..", ".", "with space", ""],
)
def test_rejects_unsafe_names(name):
    with pytest.raises(ValueError):
        sync._safe_dest_name(name)


@pytest.mark.parametrize("name", [".env", ".env.local", "config.json", "id_rsa", "A-Z_0.9"])
def test_accepts_flat_basenames(name):
    assert sync._safe_dest_name(name) == name

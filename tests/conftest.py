from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from fip.world.world import Site, build_site


@pytest.fixture(scope="session")
def tiny() -> Site:
    return build_site(5, "tiny")


@pytest.fixture(scope="session")
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Overview

Utility scripts for creating various keys. Project is managed by `uv`.

<b>Note.</b> You don't have to worry about managing your own Python interpreter or creating virtual
environments, uv will do all this for you with one caveat described below regarding corporate
network access.

# Setup

```commandline
uv sync
```

<b>Note.</b> There is an issue running uv on some corporate laptops which results in a TLS client error.
To work around this use pip.

```commandline
pip install -r requirements.txt
```

# Scripts

| Script                             | Usage                                                         |
| ---------------------------------- | ------------------------------------------------------------- |
| create_encrypting_key_from_jwks.py | Creates a public encrypting key from a JWKS endpoint output.  |
| create_signing_key_from_jwks.py    | Create a public signature verifying key from a JWKS endpoint. |
| generate_rsa_encrypting_key.py     | Creates an encrypting key pair.                               |
| generate_ec_signing_key.py         | Creates a signing key pair.                                   |

Run the scripts:

```commandline
uv run scripts/<script-name>.py
```

To use the scripts that create keys from JWKS endpoints, access the JWKS endpoint and copy the required key
into the script as per example in the script.

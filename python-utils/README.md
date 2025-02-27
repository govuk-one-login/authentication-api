# Overview

Utility scripts for creating various keys.  Project is managed by `uv`.

# Setup

```commandline
uv sync
```

Note.  There is an issue running uv on some corporate laptops which results in a TLS client error.
To work around this use command below.  This is safe because pip does not have this issue when 
downloading from this site.

```commandline
uv sync --allow-insecure-host https://files.pythonhosted.org
```

# Scripts

| Script                             | Usage                                                         |
|------------------------------------|---------------------------------------------------------------|
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
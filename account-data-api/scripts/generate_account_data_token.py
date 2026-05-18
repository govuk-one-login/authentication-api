#!/usr/bin/env python3
"""
Generate a valid Bearer access token for the account data API.

The token is an ES256 JWT signed via AWS KMS, matching the logic in
frontend-api/.../services/JwtService.java and AccessTokenConstructorService.java.

Required env vars (or pass as args):
  AUTH_TO_ACCOUNT_DATA_SIGNING_KEY  - KMS key ID or alias
  AUTH_TO_ACCOUNT_DATA_API_AUDIENCE - token audience
  AUTH_ISSUER_CLAIM                 - token issuer
  AMC_CLIENT_ID                     - client_id claim

Usage:
  python3 generate_account_data_token.py <public_subject_id> [--profile <aws_profile>] [--region <region>]
"""

import argparse
import base64
import hashlib
import json
import os
import time
import uuid

import boto3


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_to_jose_ecdsa(der_sig: bytes) -> bytes:
    """Transcode DER-encoded ECDSA signature to JOSE (fixed 64-byte concat r||s)."""
    # DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
    assert der_sig[0] == 0x30
    idx = 2
    assert der_sig[idx] == 0x02
    idx += 1
    r_len = der_sig[idx]
    idx += 1
    r = der_sig[idx : idx + r_len]
    idx += r_len
    assert der_sig[idx] == 0x02
    idx += 1
    s_len = der_sig[idx]
    idx += 1
    s = der_sig[idx : idx + s_len]

    # Strip leading zero padding and left-pad to 32 bytes
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")
    return r + s


def generate_token(
    public_subject_id: str,
    kms_key_id: str,
    audience: str,
    issuer: str,
    client_id: str,
    session_id: str,
    scope: str,
    aws_profile: str | None,
    aws_region: str,
    ttl_minutes: int = 5,
) -> str:
    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
    kms = session.client("kms")

    # Resolve alias → actual key ID (to compute kid as SHA-256 of key ID)
    pub_key_response = kms.get_public_key(KeyId=kms_key_id)
    real_key_id = pub_key_response["KeyId"]
    kid = hashlib.sha256(real_key_id.encode()).hexdigest()

    now = int(time.time())
    claims = {
        "sub": public_subject_id,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_minutes * 60,
        "scope": scope,
        "client_id": client_id,
        "sid": session_id,
        "jti": str(uuid.uuid4()),
    }

    header = {"alg": "ES256", "typ": "JWT", "kid": kid}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}"

    sign_response = kms.sign(
        KeyId=kms_key_id,
        Message=signing_input.encode(),
        MessageType="RAW",
        SigningAlgorithm="ECDSA_SHA_256",
    )

    jose_sig = der_to_jose_ecdsa(sign_response["Signature"])
    encoded_sig = b64url(jose_sig)

    return f"{signing_input}.{encoded_sig}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate an account data API access token"
    )
    parser.add_argument("public_subject_id", help="The public subject ID (sub claim)")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument(
        "--region", default="eu-west-2", help="AWS region (default: eu-west-2)"
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Session ID (sid claim); random UUID if omitted",
    )
    parser.add_argument(
        "--scope", default="passkeys.read", help="Token scope (default: passkeys.read)"
    )
    parser.add_argument(
        "--ttl", type=int, default=5, help="Token TTL in minutes (default: 5)"
    )
    args = parser.parse_args()

    kms_key_id = os.environ.get("AUTH_TO_ACCOUNT_DATA_SIGNING_KEY")
    audience = os.environ.get("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE")
    issuer = os.environ.get("AUTH_ISSUER_CLAIM")
    client_id = os.environ.get("AMC_CLIENT_ID")

    missing = [
        name
        for name, val in [
            ("AUTH_TO_ACCOUNT_DATA_SIGNING_KEY", kms_key_id),
            ("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE", audience),
            ("AUTH_ISSUER_CLAIM", issuer),
            ("AMC_CLIENT_ID", client_id),
        ]
        if not val
    ]
    if missing:
        parser.error(f"Missing required environment variables: {', '.join(missing)}")

    token = generate_token(
        public_subject_id=args.public_subject_id,
        kms_key_id=kms_key_id,
        audience=audience,
        issuer=issuer,
        client_id=client_id,
        session_id=args.session_id or str(uuid.uuid4()),
        scope=args.scope,
        aws_profile=args.profile,
        aws_region=args.region,
        ttl_minutes=args.ttl,
    )

    print(f"Bearer {token}")


if __name__ == "__main__":
    main()

import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64decode

jwks_json = """
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "x": "UPvU5NPmELrWiWSMVfDD7G8u3EJYryqPIZ46W9MAlRc",
      "y": "r77F2-KPhpvTIGEWgt5SmavSvBUHCqWUxD6RG_FJHVk",
      "alg": "ES256",
      "kid": "2785ca8e061fc5da8880c10c694e9136ac73b3643e8b6423e0caff34c5b78d96"
    }
  ]
}
"""


def create_pem():
    jwks = json.loads(jwks_json)
    key_data = jwks["keys"][0]
    x = int.from_bytes(urlsafe_b64decode(key_data["x"] + "=="), byteorder="big")
    y = int.from_bytes(urlsafe_b64decode(key_data["y"] + "=="), byteorder="big")
    curve = retrieve_elliptic_curve(key_data["crv"])
    public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(pem.decode("utf-8"))


def retrieve_elliptic_curve(crv):
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[
        crv
    ]
    return curve


if __name__ == "__main__":
    create_pem()

import json
from base64 import urlsafe_b64decode

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


jwks_json = """
{
"keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "enc",
      "alg": "RS256",
      "n": "zgTML6YZ-XUEPQprWBlWoZ9FwasmRGsdLHLgAhyNWDw4PtYaihhpSOxoI-86IeO1qAe1nfqrFGW-X37jxDBzclY_TxQkivEQqLCWmohuFcpn5dxz6SSC-WFhwLtedC8gXUv1JP4E0mgr7OKWh7t3RQcpGyTaAGXh2wywZXytVOLDcwwPb0PeFiC8MR0A8tIpYyx1yXjKcs1Aga8Xy0HFV9pU5gbB7a_XLl7j3CHePsfImYi4wG17y-jbN7-vF3GDpAqyRa78ctTZT9_WBWzPcX8yiRmHf7ID9br2MsdrTO9YyVWfI0z7OZB1GnNe5lJhGBXvd3xg4UjWbnHikliENQ",
      "kid": "80650fb36c27ab24f12438d5976ed787cf35b764a37bc9c494f7ce2105f40cee"
    }
    ]
}
"""

jwks = json.loads(jwks_json)
key_data = jwks["keys"][0]

n = int.from_bytes(urlsafe_b64decode(key_data["n"] + "=="), byteorder="big")
e = int.from_bytes(urlsafe_b64decode(key_data["e"] + "=="), byteorder="big")

public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(pem.decode("utf-8"))

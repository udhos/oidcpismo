# oidcpismo

# Generate keys

```bash
# Generate a private key:

openssl genpkey -out key-priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Generate a public key based on the private key:

openssl rsa -in key-priv.pem -out key-pub.pem -pubout -outform PEM
```

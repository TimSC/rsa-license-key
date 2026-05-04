rsa-license-key
===============

Small C++ command-line tools for generating and verifying signed software
license files. The tools build on Crypto++ and support a two-level signing
chain:

1. A master key signs a secondary public key.
2. The secondary key signs license data.
3. Verifiers check both the license signature and the secondary-key signature.

Ed25519 is the default signing algorithm. RSA-PSS with SHA-256 is also
available for users who need RSA keys.

Dependencies
------------

On Debian, Ubuntu, or Mint:

    sudo apt-get install libcrypto++-dev libxml2-dev python3

Build and Test
--------------

Build all tools:

    make

Run the basic Python test suite:

    make test

The tests exercise:

- Ed25519 master/secondary/license generation and verification.
- RSA-PSS/SHA-256 master/secondary/license generation and verification.
- Plain-text and XML license verification.
- Rejection of tampered encrypted private-key material.
- Rejection of licenses whose secondary key appears in `revoked-keys.txt`.
- Rejection of licenses where the secondary key was certified by a different master key.

Tools
-----

### genmasterpair

Generates the root/master signing key pair.

Default, Ed25519:

    ./genmasterpair

Explicit Ed25519:

    ./genmasterpair --ed25519

RSA-PSS/SHA-256:

    ./genmasterpair --rsa

Keep the encrypted master private key and its password in a highly protected
environment. The master private key is only needed to certify secondary keys.

### gensecondarypair

Generates a secondary signing key pair and signs the secondary public key with
the detected master key type.

    ./gensecondarypair

The tool autodetects whether the working directory contains an Ed25519 or RSA
master key chain. It expects exactly one key type to be present.

After generating the key pair, the tool prints the secondary key's unique
identifier:

    Key ID: 3A9F2C...

The key ID is the SHA-256 fingerprint of the raw public key bytes, encoded as
uppercase hex. Record it alongside your key-issuance records so that the key
can be revoked later if needed.

### genlicense

Generates a plain-text `license.txt` file and signs it with the detected
secondary key type.

    ./genlicense

The tool prompts for the secondary key password and then prompts for one line
of license text. Spaces in the license text are preserved.

### genxmllicense

Generates `xmllicense.xml` containing structured license data, the secondary
public key, and signatures.

    ./genxmllicense

The sample XML data is still hardcoded in `genxmllicense.cpp`; adapt it before
using this in a real product.

### verifylicense

Verifies `license.txt`, the license signature, and the secondary-key signature.

    ./verifylicense

The verifier autodetects Ed25519 or RSA-PSS/SHA-256 input files. It expects
exactly one key/signature type to be present and exits nonzero on failure.

If `revoked-keys.txt` is present in the working directory, the secondary key's
fingerprint is checked against it. A match causes verification to fail with a
`Key revoked:` message even if all signatures are valid.

### verifyxmllicense

Verifies `xmllicense.xml`, its license-data signature, and the embedded
secondary-key signature.

    ./verifyxmllicense

You can also pass a license file path:

    ./verifyxmllicense path/to/xmllicense.xml

Like `verifylicense`, this tool checks `revoked-keys.txt` if the file exists,
computing the fingerprint from the secondary public key embedded in the XML.

Generated Files
---------------

Ed25519 master files:

- `master-ed25519-privkey-enc.txt`
- `master-ed25519-privkey-enc.txt.salt`
- `master-ed25519-privkey-iv.txt`
- `master-ed25519-pubkey.txt`

Ed25519 secondary/license files:

- `secondary-ed25519-privkey-enc.txt`
- `secondary-ed25519-privkey-enc.txt.salt`
- `secondary-ed25519-privkey-iv.txt`
- `secondary-ed25519-pubkey.txt`
- `secondary-ed25519-pubkey-sig.txt`
- `license-ed25519-sig.txt`

RSA master files:

- `master-privkey-enc.txt`
- `master-privkey-enc.txt.salt`
- `master-privkey-iv.txt`
- `master-pubkey.txt`

RSA secondary/license files:

- `secondary-privkey-enc.txt`
- `secondary-privkey-enc.txt.salt`
- `secondary-privkey-iv.txt`
- `secondary-pubkey.txt`
- `secondary-pubkey-sig.txt`
- `license-sig.txt`

Common license outputs:

- `license.txt`
- `xmllicense.xml`

Private-Key Protection
----------------------

Private keys are encrypted with AES-GCM. Passwords are processed with
PBKDF2-HMAC-SHA256 using a per-key random salt and 200,000 iterations.

AES-GCM provides authenticated encryption, so tampering with encrypted private
keys is detected before decrypted bytes are parsed as key material.

The current file format stores encrypted key material, nonce/IV, and salt as
separate files. Treat all files belonging to a key as one unit.

Windows Web Check Helper
------------------------

`winwebcheck.cpp` is a Windows-only helper for checking a key against an HTTPS
endpoint. It sends the key in a POST body and requires the server response to
be signed with Ed25519.

Before using it, set `LICENSE_RESPONSE_PUBKEY_BASE64` to the server response
signing public key. The expected response body is:

    1
    <base64 Ed25519 signature>

The signature is over:

    license-response:v1
    key=<key>
    status=1

Key Revocation
--------------

To revoke a secondary key, add its key ID (printed by `gensecondarypair`) to a
`revoked-keys.txt` file, one ID per line, in the directory where verification
runs:

    echo "3A9F2C..." >> revoked-keys.txt

Both `verifylicense` and `verifyxmllicense` check this file on every run. If
the secondary key used to sign the license matches any entry, verification fails
regardless of whether the signatures are cryptographically valid.

The key ID is the SHA-256 fingerprint of the raw public key bytes (uppercase
hex). It is derived solely from the public key, so it is stable and can be
computed from any copy of the public key file.

Notes and Limitations
---------------------

- Existing key files generated by older versions must be regenerated because
  the private-key encryption format changed.
- Password input currently uses standard terminal input and may echo depending
  on the shell/terminal.
- XML license generation is a sample. It escapes XML attributes correctly for
  this narrow format, but production systems should use a structured XML
  builder and canonical signing format.
- Adapt license contents, policy checks, and revocation handling to your own
  product before shipping.

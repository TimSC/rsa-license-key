rsa-license-key
===============

Key management tools for software licensing and activation. C++ and BSD license. Based on crypto++.

On debian/ubuntu/mint:

    sudo apt-get install libcrypto++-dev libxml2-dev

Compile using "make"

genmasterpair - to generate master keys. Keep the private master key in an ultra secure place.

gensecondarypair - to generate a secondary key that is signed by the master key. Keep the secondary master key secure, but if it is compromised, it can be revoked.

genxmllicense and genlicense - generate license files that are signed by the secondary key (which is in turn signed by the master key)

verifyxmllicense and verifylicense - verify signatures in the license file

Adapt the license generation and verification to your own needs.


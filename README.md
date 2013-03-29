rsa-license-key
===============

Key management tools for software licensing and activation. C++ and BSD license. Based on crypto++.

Compile using "make"

genmasterpair - to generate master keys

gensecondarypair - to generate a secondary key that is signed by the master key

genxmllicense and genlicense - generate license files that are signed by the secondary key (which is in turn signed by the master key)

verifyxmllicense and verifylicense - verify signatures in the license file

Adapt the license generation and verification to your own needs.


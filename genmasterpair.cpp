// Generate the root/master signing key pair; Ed25519 by default, or RSA-PSS with --rsa.
//g++ genmasterpair.cpp -lcrypto++ -o genmasterpair

#include <string>
#include <cstring>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/filters.h>
#include <crypto++/pwdbased.h>
#include <crypto++/sha.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

const unsigned int PBKDF2_ITERATIONS = 200000;
const unsigned int PBKDF2_SALT_BYTES = 16;
const unsigned int ENCRYPTION_IV_BYTES = 12;

string SaltFilename(const char *encFilename)
{
	return string(encFilename) + ".salt";
}

SecByteBlock DeriveEncryptionKey(string pass, string salt)
{
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
	pbkdf.DeriveKey(
		key,
		key.size(),
		0,
		(const CryptoPP::byte *)pass.data(),
		pass.size(),
		(const CryptoPP::byte *)salt.data(),
		salt.size(),
		PBKDF2_ITERATIONS);
	return key;
}

void SaveEncrypted(string plaintext, string pass, const char *encFilename, const char *ivFilename, AutoSeededRandomPool &rng)
{
	SecByteBlock salt(PBKDF2_SALT_BYTES);
	rng.GenerateBlock(salt, salt.size());
	string saltStr((char *)salt.begin(), salt.size());
	SecByteBlock key = DeriveEncryptionKey(pass, saltStr);
	
	SecByteBlock iv(ENCRYPTION_IV_BYTES);
	rng.GenerateBlock(iv, iv.size());

	//Encrypt private key
	string encPrivKeyStr;
	GCM<AES>::Encryption encryption;
	encryption.SetKeyWithIV(key, key.size(), iv, iv.size());
	StringSource(plaintext, true, new AuthenticatedEncryptionFilter(encryption, new StringSink(encPrivKeyStr)));

	//Save private key to file
	StringSource encPrivKeySrc(encPrivKeyStr, true);
	Base64Encoder sink(new FileSink(encFilename));
	encPrivKeySrc.CopyTo(sink);
	sink.MessageEnd();

	//Save initialization vector key to file
	StringSource ivStr(iv, iv.size(), true);
	Base64Encoder sink2(new FileSink(ivFilename));
	ivStr.CopyTo(sink2);
	sink2.MessageEnd();

	//Save password salt
	StringSource saltSrc(saltStr, true);
	Base64Encoder sink3(new FileSink(SaltFilename(encFilename).c_str()));
	saltSrc.CopyTo(sink3);
	sink3.MessageEnd();
}

void GenRsaKeyPair(string pass, AutoSeededRandomPool &rng)
{
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024*8);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	string privKeyDer;
	StringSink privKeyDerSink(privKeyDer);
	privkey.DEREncode(privKeyDerSink);

	SaveEncrypted(privKeyDer, pass, "master-privkey-enc.txt", "master-privkey-iv.txt", rng);

	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("master-pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
}

void GenEd25519KeyPair(string pass, AutoSeededRandomPool &rng)
{
	ed25519::Signer edSigner(rng);
	string edPrivKeyDer;
	edSigner.GetPrivateKey().Save(StringSink(edPrivKeyDer).Ref());
	SaveEncrypted(edPrivKeyDer, pass, "master-ed25519-privkey-enc.txt", "master-ed25519-privkey-iv.txt", rng);

	ed25519::Verifier edVerifier(edSigner);
	Base64Encoder edPubkeysink(new FileSink("master-ed25519-pubkey.txt"));
	edVerifier.GetPublicKey().Save(edPubkeysink);
	edPubkeysink.MessageEnd();
}

int main(int argc, char **argv)
{
	bool useEd25519 = true;
	if (argc > 1)
	{
		if (strcmp(argv[1], "--rsa") == 0)
		{
			useEd25519 = false;
		}
		else if (strcmp(argv[1], "--ed25519") == 0)
		{
			useEd25519 = true;
		}
		else
		{
			cout << "Usage: genmasterpair [--ed25519|--rsa]" << endl;
			return 1;
		}
	}

	cout << "Enter new master key password" << endl;
	string pass;
	cin >> pass;

	AutoSeededRandomPool rng;
	if (useEd25519)
	{
		GenEd25519KeyPair(pass, rng);
	}
	else
	{
		GenRsaKeyPair(pass, rng);
	}
}

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
#include <crypto++/modes.h>
#include <crypto++/ripemd.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

void SaveEncrypted(string plaintext, string pass, const char *encFilename, const char *ivFilename, AutoSeededRandomPool &rng)
{
	//Hash the pass phrase to create 128 bit key
	string hashedPass;
	RIPEMD128 hash;
	StringSource(pass, true, new HashFilter(hash, new StringSink(hashedPass)));
	
	// Generate a random IV
	CryptoPP::byte iv[AES::BLOCKSIZE];
	rng.GenerateBlock(iv, AES::BLOCKSIZE);

	//Encrypt private key
	CFB_Mode<AES>::Encryption cfbEncryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	CryptoPP::byte encPrivKey[plaintext.length()];
	cfbEncryption.ProcessData(encPrivKey, (const CryptoPP::byte*)plaintext.c_str(), plaintext.length());
	string encPrivKeyStr((char *)encPrivKey, plaintext.length());

	//Save private key to file
	StringSource encPrivKeySrc(encPrivKeyStr, true);
	Base64Encoder sink(new FileSink(encFilename));
	encPrivKeySrc.CopyTo(sink);
	sink.MessageEnd();

	//Save initialization vector key to file
	StringSource ivStr(iv, AES::BLOCKSIZE, true);
	Base64Encoder sink2(new FileSink(ivFilename));
	ivStr.CopyTo(sink2);
	sink2.MessageEnd();
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

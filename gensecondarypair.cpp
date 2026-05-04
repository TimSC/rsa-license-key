// Generate a secondary signing key pair and certify it with the detected master key type.
//g++ gensecondarypair.cpp -lcrypto++ -o gensecondarypair

#include <string>
#include <fstream>
#include <exception>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/filters.h>
#include <crypto++/pwdbased.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

const unsigned int PBKDF2_ITERATIONS = 200000;
const unsigned int PBKDF2_SALT_BYTES = 16;
const unsigned int ENCRYPTION_IV_BYTES = 12;

bool FileExists(const char *filename)
{
	ifstream file(filename);
	return file.good();
}

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

string ReadEncrypted(string encFilename, string ivFilename, string pass)
{
	//Read private key
	string encPrivKey;
	StringSink encPrivKeySink(encPrivKey);
	FileSource file(encFilename.c_str(), true, new Base64Decoder);
	file.CopyTo(encPrivKeySink);

	//Read initialization vector
	string iv;
	FileSource file2(ivFilename.c_str(), true, new Base64Decoder(new StringSink(iv)));

	//Read password salt
	string salt;
	FileSource saltFile(SaltFilename(encFilename.c_str()).c_str(), true, new Base64Decoder(new StringSink(salt)));
	SecByteBlock key = DeriveEncryptionKey(pass, salt);

	//Decrypt private key
	string plaintext;
	GCM<AES>::Decryption decryption;
	decryption.SetKeyWithIV(key, key.size(), (const CryptoPP::byte *)iv.data(), iv.size());
	StringSource(encPrivKey, true, new AuthenticatedDecryptionFilter(decryption, new StringSink(plaintext)));
	return plaintext;
}

string GenKeyPair(AutoSeededRandomPool &rng, string pass)
{
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024*4);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	string privKeyStr;
	StringSink privKeyStrSink(privKeyStr);
	//Base64Encoder privkeysink(new FileSink("secondary-privkey.txt"));
	privkey.DEREncode(privKeyStrSink);
	privKeyStrSink.MessageEnd();
	 
	SaveEncrypted(privKeyStr, pass, "secondary-privkey-enc.txt", "secondary-privkey-iv.txt", rng);

	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("secondary-pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

	string pubkeyStr;
	Base64Encoder pubkeysink2(new StringSink(pubkeyStr));
	pubkey.DEREncode(pubkeysink2);
	pubkeysink2.MessageEnd();

	return pubkeyStr;
}

string GenEd25519KeyPair(AutoSeededRandomPool &rng, string pass)
{
	ed25519::Signer signer(rng);

	string privKeyStr;
	signer.GetPrivateKey().Save(StringSink(privKeyStr).Ref());
	SaveEncrypted(privKeyStr, pass, "secondary-ed25519-privkey-enc.txt", "secondary-ed25519-privkey-iv.txt", rng);

	ed25519::Verifier verifier(signer);
	Base64Encoder pubkeysink(new FileSink("secondary-ed25519-pubkey.txt"));
	verifier.GetPublicKey().Save(pubkeysink);
	pubkeysink.MessageEnd();

	string pubkeyStr;
	Base64Encoder pubkeysink2(new StringSink(pubkeyStr));
	verifier.GetPublicKey().Save(pubkeysink2);
	pubkeysink2.MessageEnd();

	return pubkeyStr;
}

void SignSecondaryKey(AutoSeededRandomPool &rng, string strContents, string pass)
{
	string masterKeyStr = ReadEncrypted("master-privkey-enc.txt", "master-privkey-iv.txt", pass);
	StringSource masterKey(masterKeyStr, true, NULL);

	RSA::PrivateKey privateKey;
	privateKey.Load(masterKey);

	//Sign message
	RSASS<PSS, SHA256>::Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(CryptoPP::byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	Base64Encoder enc(new FileSink("secondary-pubkey-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

void SignSecondaryEd25519Key(AutoSeededRandomPool &rng, string strContents, string pass)
{
	string masterKeyStr = ReadEncrypted("master-ed25519-privkey-enc.txt", "master-ed25519-privkey-iv.txt", pass);
	StringSource masterKeySrc(masterKeyStr, true, NULL);

	ed25519PrivateKey privateKey;
	privateKey.Load(masterKeySrc);
	ed25519::Signer privkey(privateKey);

	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(CryptoPP::byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	Base64Encoder enc(new FileSink("secondary-ed25519-pubkey-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

int main()
{
	cout << "Enter existing master key password" << endl;
	string pass;
	cin >> pass;

	cout << "Enter new secondary key password" << endl;
	string pass2;
	cin >> pass2;

	try
	{
		AutoSeededRandomPool rng;
		bool hasRsaMaster = FileExists("master-privkey-enc.txt") && FileExists("master-privkey-enc.txt.salt") && FileExists("master-pubkey.txt");
		bool hasEdMaster = FileExists("master-ed25519-privkey-enc.txt") && FileExists("master-ed25519-privkey-enc.txt.salt") && FileExists("master-ed25519-pubkey.txt");

		if (hasRsaMaster == hasEdMaster)
		{
			cout << "error: expected exactly one master key type" << endl;
			return 1;
		}

		if (hasEdMaster)
		{
			string edPubkey = GenEd25519KeyPair(rng, pass2);
			SignSecondaryEd25519Key(rng, edPubkey, pass);
		}
		else
		{
			string pubkey = GenKeyPair(rng, pass2);
			SignSecondaryKey(rng, pubkey, pass);
		}
	}
	catch(CryptoPP::Exception &err)
	{
		cout << "Crypto error: " << err.what() << endl;
		return 1;
	}
	catch(std::exception &err)
	{
		cout << "error: " << err.what() << endl;
		return 1;
	}
}

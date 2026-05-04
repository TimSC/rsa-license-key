// Generate a plain-text license file and sign it with the detected secondary key type.
//g++ genlicense.cpp -lcrypto++ -o genlicense

#include <string>
#include <fstream>
#include <exception>
#include <limits>
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

void SignLicense(AutoSeededRandomPool &rng, string strContents, string pass)
{

	string privateKeyStr = ReadEncrypted("secondary-privkey-enc.txt", "secondary-privkey-iv.txt", pass);
	StringSource privateKeySrc(privateKeyStr, true, NULL);

	//Decode key
	RSA::PrivateKey privateKey;
	privateKey.Load(privateKeySrc);

	//Sign message
	RSASS<PSS, SHA256>::Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(CryptoPP::byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	FileSink out("license.txt");
	out.Put((CryptoPP::byte const*) strContents.data(), strContents.size());

	//Save result
	Base64Encoder enc(new FileSink("license-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

void SignLicenseEd25519(AutoSeededRandomPool &rng, string strContents, string pass)
{
	string privateKeyStr = ReadEncrypted("secondary-ed25519-privkey-enc.txt", "secondary-ed25519-privkey-iv.txt", pass);
	StringSource privateKeySrc(privateKeyStr, true, NULL);

	ed25519PrivateKey privateKey;
	privateKey.Load(privateKeySrc);
	ed25519::Signer privkey(privateKey);

	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(CryptoPP::byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	Base64Encoder enc(new FileSink("license-ed25519-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

int main()
{
	cout << "Enter existing secondary key password" << endl;
	string pass;
	cin >> pass;

	AutoSeededRandomPool rng;
	cout << "Enter license text" << endl;
	cin.ignore(numeric_limits<streamsize>::max(), '\n');
	string licenseText;
	getline(cin, licenseText);

	try
	{
		bool hasRsaSecondary = FileExists("secondary-privkey-enc.txt") && FileExists("secondary-privkey-enc.txt.salt") && FileExists("secondary-pubkey.txt");
		bool hasEdSecondary = FileExists("secondary-ed25519-privkey-enc.txt") && FileExists("secondary-ed25519-privkey-enc.txt.salt") && FileExists("secondary-ed25519-pubkey.txt");

		if (hasRsaSecondary == hasEdSecondary)
		{
			cout << "error: expected exactly one secondary key type" << endl;
			return 1;
		}

		if (hasEdSecondary)
		{
			FileSink out("license.txt");
			out.Put((CryptoPP::byte const*) licenseText.data(), licenseText.size());
			SignLicenseEd25519(rng, licenseText, pass);
		}
		else
		{
			SignLicense(rng, licenseText, pass);
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

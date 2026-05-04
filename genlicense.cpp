// Generate a plain-text license file and sign it with the detected secondary key type.
//g++ genlicense.cpp -lcrypto++ -o genlicense

#include <string>
#include <fstream>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/ripemd.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

bool FileExists(const char *filename)
{
	ifstream file(filename);
	return file.good();
}

string ReadEncrypted(string encFilename, string ivFilename, string pass)
{
	//Read private key
	string encPrivKey;
	StringSink encPrivKeySink(encPrivKey);
	FileSource file(encFilename.c_str(), true, new Base64Decoder);
	file.CopyTo(encPrivKeySink);

	//Read initialization vector
	CryptoPP::byte iv[AES::BLOCKSIZE];
	CryptoPP::ByteQueue bytesIv;
	FileSource file2(ivFilename.c_str(), true, new Base64Decoder);
	file2.TransferTo(bytesIv);
	bytesIv.MessageEnd();
	bytesIv.Get(iv, AES::BLOCKSIZE);

	//Hash the pass phrase to create 128 bit key
	string hashedPass;
	RIPEMD128 hash;
	StringSource(pass, true, new HashFilter(hash, new StringSink(hashedPass)));

	//Decrypt private key
	CryptoPP::byte plaintext[encPrivKey.length()];
	CFB_Mode<AES>::Decryption cfbDecryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	cfbDecryption.ProcessData(plaintext, (CryptoPP::byte *)encPrivKey.c_str(), encPrivKey.length());
	return string((char *)plaintext, encPrivKey.length());
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
	string licenseText = "Licensed to BOB";

	bool hasRsaSecondary = FileExists("secondary-privkey-enc.txt") && FileExists("secondary-pubkey.txt");
	bool hasEdSecondary = FileExists("secondary-ed25519-privkey-enc.txt") && FileExists("secondary-ed25519-pubkey.txt");

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

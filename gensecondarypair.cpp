// Generate a secondary signing key pair and certify it with the detected master key type.
//g++ gensecondarypair.cpp -lcrypto++ -o gensecondarypair

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

	AutoSeededRandomPool rng;
	bool hasRsaMaster = FileExists("master-privkey-enc.txt") && FileExists("master-pubkey.txt");
	bool hasEdMaster = FileExists("master-ed25519-privkey-enc.txt") && FileExists("master-ed25519-pubkey.txt");

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

//g++ gensecondarypair.cpp -lcrypto++ -o gensecondarypair

#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/ripemd.h>
using namespace CryptoPP;

string GenKeyPair(AutoSeededRandomPool &rng)
{
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024*4);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	Base64Encoder privkeysink(new FileSink("secondary-privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	 
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

void SignSecondaryKey(AutoSeededRandomPool &rng, string strContents, string pass)
{
	//Read private key
	string encMasterPrivKey;
	StringSink encMasterPrivKeySink(encMasterPrivKey);
	FileSource file("master-privkey-enc.txt", true, new Base64Decoder);
	file.CopyTo(encMasterPrivKeySink);

	//Read initialization vector
	byte iv[AES::BLOCKSIZE];
	CryptoPP::ByteQueue bytesIv;
	FileSource file2("master-privkey-iv.txt", true, new Base64Decoder);
	file2.TransferTo(bytesIv);
	bytesIv.MessageEnd();
	bytesIv.Get(iv, AES::BLOCKSIZE);

	cout << "IV:";
	for(unsigned i=0;i<AES::BLOCKSIZE;i++)
	{
		cout << (int)(iv[i]) << ",";
	}
	cout << endl;

	//Hash the pass phrase to create 128 bit key
	string hashedPass;
	RIPEMD128 hash;
	StringSource(pass, true, new HashFilter(hash, new StringSink(hashedPass)));

	//Decrypt master key
	byte test[encMasterPrivKey.length()];
	CFB_Mode<AES>::Decryption cfbDecryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	cfbDecryption.ProcessData(test, (byte *)encMasterPrivKey.c_str(), encMasterPrivKey.length());
	StringSource masterKey(test, encMasterPrivKey.length(), true, new Base64Decoder);
	cout << encMasterPrivKey.length() << endl;

	cout << "Key:";
	for(unsigned i=0;i<50;i++)
	{
		cout << test[i];
	}
	cout << "...";
	for(unsigned i=encMasterPrivKey.length()-50;i<encMasterPrivKey.length();i++)
	{
		cout << test[i];
	}
	cout << endl;

	RSA::PrivateKey privateKey;
	cout << "1" << endl;
	privateKey.Load(masterKey);
	cout << "x" << endl;

	//Sign message
	RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	Base64Encoder enc(new FileSink("secondary-pubkey-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

int main()
{
	cout << "Enter master key password" << endl;
	string pass;
	cin >> pass;

	AutoSeededRandomPool rng;
	string pubkey = GenKeyPair(rng);
	SignSecondaryKey(rng, pubkey, pass);
}



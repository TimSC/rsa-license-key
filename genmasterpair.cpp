//g++ genmasterpair.cpp -lcrypto++ -o genmasterpair

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

void GenKeyPair()
{
	cout << "Enter master key password" << endl;
	string pass;
	cin >> pass;

	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024*8);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	string privKeyDer;
	Base64Encoder privkeysink(new StringSink(privKeyDer));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	//Hash the pass phrase to create 128 bit key
	string hashedPass;
	RIPEMD128 hash;
	StringSource(pass, true, new HashFilter(hash, new StringSink(hashedPass)));
	
	// Generate a random IV
	byte iv[AES::BLOCKSIZE];
	rng.GenerateBlock(iv, AES::BLOCKSIZE);

	RSA::PrivateKey privateKey2;
	StringSource x2(privKeyDer, true, new Base64Decoder);
	cout << "1" << endl;
	privateKey2.Load(x2);
	cout << "done" << endl;

	cout << "IV:";
	for(unsigned i=0;i<AES::BLOCKSIZE;i++)
	{
		cout << (int)(iv[i]) << ",";
	}
	cout << endl;

	cout << "Key:";
	for(unsigned i=0;i<50;i++)
	{
		cout << privKeyDer[i];
	}
	cout << "...";
	for(unsigned i=privKeyDer.length()-50;i<privKeyDer.length();i++)
	{
		cout << privKeyDer[i];
	}
	cout << endl;

	//Encrypt private key
	CFB_Mode<AES>::Encryption cfbEncryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	byte encPrivKey[privKeyDer.length()+1];
	cfbEncryption.ProcessData(encPrivKey, (const byte*)privKeyDer.c_str(), privKeyDer.length());
	string encPrivKeyStr((char *)encPrivKey, privKeyDer.length());

	byte test[privKeyDer.length()];	
	CFB_Mode<AES>::Decryption cfbDecryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	cfbDecryption.ProcessData(test, encPrivKey, privKeyDer.length());
	cout << privKeyDer.length() << endl;

	RSA::PrivateKey privateKey;
	StringSource x((const char *)test, privKeyDer.length(), new Base64Decoder);
	cout << "2" << endl;
	privateKey.Load(x);
	cout << "done" << endl;

	//Save private key to file
	StringSource encPrivKeySrc(encPrivKeyStr, true);
	Base64Encoder sink(new FileSink("master-privkey-enc.txt"));
	encPrivKeySrc.CopyTo(sink);
	sink.MessageEnd();

	//Save initialization vector key to file
	StringSource ivStr(iv, AES::BLOCKSIZE, true);
	Base64Encoder sink2(new FileSink("master-privkey-iv.txt"));
	ivStr.CopyTo(sink2);
	sink2.MessageEnd();

	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("master-pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();



}

int main()
{
	GenKeyPair();
}



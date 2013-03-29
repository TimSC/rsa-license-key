//g++ genlicense.cpp -lcrypto++ -o genlicense

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

void SignLicense(AutoSeededRandomPool &rng, string strContents, string pass)
{

	//Read private key
	string encPrivKey;
	StringSink encPrivKeySink(encPrivKey);
	FileSource file("secondary-privkey-enc.txt", true, new Base64Decoder);
	file.CopyTo(encPrivKeySink);

	//Read initialization vector
	byte iv[AES::BLOCKSIZE];
	CryptoPP::ByteQueue bytesIv;
	FileSource file2("secondary-privkey-iv.txt", true, new Base64Decoder);
	file2.TransferTo(bytesIv);
	bytesIv.MessageEnd();
	bytesIv.Get(iv, AES::BLOCKSIZE);

	//Hash the pass phrase to create 128 bit key
	string hashedPass;
	RIPEMD128 hash;
	StringSource(pass, true, new HashFilter(hash, new StringSink(hashedPass)));

	//Decrypt private key
	byte test[encPrivKey.length()];
	CFB_Mode<AES>::Decryption cfbDecryption((const unsigned char*)hashedPass.c_str(), hashedPass.length(), iv);
	cfbDecryption.ProcessData(test, (byte *)encPrivKey.c_str(), encPrivKey.length());
	StringSource privateKeySrc(test, encPrivKey.length(), true, NULL);

	//Decode key
	RSA::PrivateKey privateKey;
	privateKey.Load(privateKeySrc);

	//Sign message
	RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	FileSink out("license.txt");
	out.Put((byte const*) strContents.data(), strContents.size());

	//Save result
	Base64Encoder enc(new FileSink("license-sig.txt"));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();
}

int main()
{
	cout << "Enter existing secondary key password" << endl;
	string pass;
	cin >> pass;

	AutoSeededRandomPool rng;
	SignLicense(rng, "Licensed to BOB", pass);
}



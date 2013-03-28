//g++ genlicense.cpp -lcrypto++ -o genlicense

#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
using namespace CryptoPP;

void SignLicense(AutoSeededRandomPool &rng, string strContents)
{
	//Read private key
	CryptoPP::ByteQueue bytes;
	FileSource file("secondary-privkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);

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
	AutoSeededRandomPool rng;
	SignLicense(rng, "Licensed to BOB");
}



//g++ verifylicense.cpp -lcrypto++ -o verifylicense
#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
using namespace CryptoPP;

int VerifyLicense()
{
	try
	{
		//Read public key
		CryptoPP::ByteQueue bytes;
		FileSource file("secondary-pubkey.txt", true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		RSA::PublicKey pubKey;
		pubKey.Load(bytes);

		RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

		//Read signed message
		string signedTxt;
		FileSource("license.txt", true, new StringSink(signedTxt));
		string sigStr;
		FileSource sigFile("license-sig.txt", true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		//Verify signature
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout << "License Signature OK" << endl;

	}
	catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
	{
		cout << err.what() << endl;
		return 0;
	}
	catch(CryptoPP::Exception &err)
	{
		cout << "Crypto error: " << err.what() << endl;
		return 0;
	}
	catch(std::exception &err)
	{
		cout << "Verification error: " << err.what() << endl;
		return 0;
	}
	return 1;
}

int VerifySecondaryKey()
{
	try
	{
		//Read public key
		CryptoPP::ByteQueue bytes;
		FileSource file("master-pubkey.txt", true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		RSA::PublicKey pubKey;
		pubKey.Load(bytes);

		RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

		//Read signed message
		string signedTxt;
		FileSource("secondary-pubkey.txt", true, new StringSink(signedTxt));
		string sigStr;
		FileSource sigFile("secondary-pubkey-sig.txt", true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		//Verify signature
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout << "Secondary Key OK" << endl;

	}
	catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
	{
		cout << err.what() << endl;
		return 0;
	}
	catch(CryptoPP::Exception &err)
	{
		cout << "Crypto error: " << err.what() << endl;
		return 0;
	}
	catch(std::exception &err)
	{
		cout << "Verification error: " << err.what() << endl;
		return 0;
	}
	return 1;
}

int main()
{
	int ret1 = VerifySecondaryKey();
	int ret2 = VerifyLicense();

	return (ret1 && ret2) ? 0 : 1;
}


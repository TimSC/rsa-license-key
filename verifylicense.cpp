// Verify a plain-text license and its secondary key chain using the detected signature type.
//g++ verifylicense.cpp -lcrypto++ -o verifylicense
#include <string>
#include <fstream>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

bool FileExists(const char *filename)
{
	ifstream file(filename);
	return file.good();
}

int VerifyRsaSignatureText(string signedTxt, string sigFilename, string pubKeyFilename, string okMessage)
{
	try
	{
		//Read public key
		CryptoPP::ByteQueue bytes;
		FileSource file(pubKeyFilename.c_str(), true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		RSA::PublicKey pubKey;
		pubKey.Load(bytes);

		RSASS<PSS, SHA256>::Verifier verifier(pubKey);

		//Read signed message
		string sigStr;
		FileSource sigFile(sigFilename.c_str(), true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		//Verify signature
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout << okMessage << endl;

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

int VerifyEd25519SignatureText(string signedTxt, string sigFilename, string pubKeyFilename, string okMessage)
{
	try
	{
		CryptoPP::ByteQueue bytes;
		FileSource file(pubKeyFilename.c_str(), true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		ed25519PublicKey pubKey;
		pubKey.Load(bytes);

		ed25519::Verifier verifier(pubKey);

		string sigStr;
		FileSource sigFile(sigFilename.c_str(), true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout << okMessage << endl;
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

int VerifyLicense()
{
	string signedTxt;
	try
	{
		FileSource("license.txt", true, new StringSink(signedTxt));
	}
	catch(CryptoPP::Exception &err)
	{
		cout << "Crypto error: " << err.what() << endl;
		return 0;
	}

	bool hasRsaLicense = FileExists("license-sig.txt") && FileExists("secondary-pubkey.txt");
	bool hasEdLicense = FileExists("license-ed25519-sig.txt") && FileExists("secondary-ed25519-pubkey.txt");

	if (hasRsaLicense == hasEdLicense)
	{
		cout << "error: expected exactly one license signature type" << endl;
		return 0;
	}

	if (hasEdLicense)
	{
		return VerifyEd25519SignatureText(signedTxt, "license-ed25519-sig.txt", "secondary-ed25519-pubkey.txt", "License Ed25519 Signature OK");
	}
	return VerifyRsaSignatureText(signedTxt, "license-sig.txt", "secondary-pubkey.txt", "License RSA-PSS Signature OK");
}

int VerifySecondaryKey()
{
	bool hasRsaSecondary = FileExists("secondary-pubkey.txt") && FileExists("secondary-pubkey-sig.txt") && FileExists("master-pubkey.txt");
	bool hasEdSecondary = FileExists("secondary-ed25519-pubkey.txt") && FileExists("secondary-ed25519-pubkey-sig.txt") && FileExists("master-ed25519-pubkey.txt");

	if (hasRsaSecondary == hasEdSecondary)
	{
		cout << "error: expected exactly one secondary key type" << endl;
		return 0;
	}

	string signedTxt;
	try
	{
		if (hasEdSecondary)
		{
			FileSource("secondary-ed25519-pubkey.txt", true, new StringSink(signedTxt));
		}
		else
		{
			FileSource("secondary-pubkey.txt", true, new StringSink(signedTxt));
		}
	}
	catch(CryptoPP::Exception &err)
	{
		cout << "Crypto error: " << err.what() << endl;
		return 0;
	}

	if (hasEdSecondary)
	{
		return VerifyEd25519SignatureText(signedTxt, "secondary-ed25519-pubkey-sig.txt", "master-ed25519-pubkey.txt", "Secondary Ed25519 Key OK");
	}
	return VerifyRsaSignatureText(signedTxt, "secondary-pubkey-sig.txt", "master-pubkey.txt", "Secondary RSA-PSS Key OK");
}

int main()
{
	int ret1 = VerifySecondaryKey();
	int ret2 = VerifyLicense();

	return (ret1 && ret2) ? 0 : 1;
}

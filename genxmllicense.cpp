// Generate an XML license containing signed license data and the certified secondary public key.
//g++ genxmllicense.cpp -lcrypto++ -o genxmllicense

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
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

string SignLicense(AutoSeededRandomPool &rng, string strContents, string pass)
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
	string out;
	Base64Encoder enc(new StringSink(out));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();

	return out;
}

string SignLicenseEd25519(AutoSeededRandomPool &rng, string strContents, string pass)
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

	string out;
	Base64Encoder enc(new StringSink(out));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();

	return out;
}

string XmlAttributeEscape(const string& str)
{
	string out;
	for (size_t i = 0; i < str.size(); i++)
	{
		switch (str[i])
		{
			case '&': out.append("&amp;"); break;
			case '<': out.append("&lt;"); break;
			case '>': out.append("&gt;"); break;
			case '"': out.append("&quot;"); break;
			case '\'': out.append("&apos;"); break;
			default: out.push_back(str[i]); break;
		}
	}
	return out;
}

string SerialiseKeyPairs(vector<vector<std::string> > &info)
{
	string out;
	for(unsigned int pairNum = 0;pairNum < info.size();pairNum++)
	{
		out.append("<data k=\"");
		out.append(XmlAttributeEscape(info[pairNum][0]));
		out.append("\" v=\"");
		out.append(XmlAttributeEscape(info[pairNum][1]));
		out.append("\" />");
	}

	return out;
}

string GetFileContent(string filename)
{
	ifstream fi(filename.c_str());
	if(!fi)
	{
		runtime_error("Could not open file");
	}

    // get length of file:
    fi.seekg (0, fi.end);
    int length = fi.tellg();
    fi.seekg (0, fi.beg);

	stringstream test;
	test << fi.rdbuf();

	return test.str();
}

int main()
{
	cout << "Enter existing secondary key password" << endl;
	string pass;
	cin >> pass;

	vector<vector<std::string> > info;
	
	vector<string> pair;
	pair.push_back("licensee");
	pair.push_back("John Doe, Big Institute, Belgium");
	info.push_back(pair);

	pair.clear();
	pair.push_back("functions");
	pair.push_back("feature1, feature2");
	info.push_back(pair);

	string serialisedInfo = SerialiseKeyPairs(info);

	AutoSeededRandomPool rng;

	try
	{
		bool hasRsaSecondary = FileExists("secondary-privkey-enc.txt") && FileExists("secondary-privkey-enc.txt.salt") && FileExists("secondary-pubkey.txt");
		bool hasEdSecondary = FileExists("secondary-ed25519-privkey-enc.txt") && FileExists("secondary-ed25519-privkey-enc.txt.salt") && FileExists("secondary-ed25519-pubkey.txt");

		if (hasRsaSecondary == hasEdSecondary)
		{
			cout << "error: expected exactly one secondary key type" << endl;
			return 1;
		}

		//Encode as xml
		string xml="<license>";
		xml.append("<info>");
		xml.append(serialisedInfo);
		xml.append("</info>");
		if (hasEdSecondary)
		{
			string edInfoSig = SignLicenseEd25519(rng, serialisedInfo, pass);
			xml.append("<edinfosig>");
			xml.append(edInfoSig);
			xml.append("</edinfosig>");
			xml.append("<edkey>");
			xml.append(GetFileContent("secondary-ed25519-pubkey.txt"));
			xml.append("</edkey>");
			xml.append("<edkeysig>");
			xml.append(GetFileContent("secondary-ed25519-pubkey-sig.txt"));
			xml.append("</edkeysig>");
		}
		else
		{
			string infoSig = SignLicense(rng, serialisedInfo, pass);
			xml.append("<infosig>");
			xml.append(infoSig);
			xml.append("</infosig>");
			xml.append("<key>");
			xml.append(GetFileContent("secondary-pubkey.txt"));
			xml.append("</key>");
			xml.append("<keysig>");
			xml.append(GetFileContent("secondary-pubkey-sig.txt"));
			xml.append("</keysig>");
		}
		xml.append("</license>");
		
		//cout << xml << endl;

		ofstream out("xmllicense.xml");
		out << xml;
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

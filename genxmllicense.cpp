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

void myReplace(std::string& str, const std::string& oldStr, const std::string& newStr)
{
	//From http://stackoverflow.com/a/1494435
	size_t pos = 0;
	while((pos = str.find(oldStr, pos)) != std::string::npos)
	{
		str.replace(pos, oldStr.length(), newStr);
		pos += newStr.length();
	}
}

string SerialiseKeyPairs(vector<vector<std::string> > &info)
{
	string out;
	for(unsigned int pairNum = 0;pairNum < info.size();pairNum++)
	{
		out.append("<data k=\"");
		myReplace(info[pairNum][0], "\"", "&quot;");
		out.append(info[pairNum][0]);
		out.append("\" v=\"");
		myReplace(info[pairNum][1], "\"", "&quot;");
		out.append(info[pairNum][1]);
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

	bool hasRsaSecondary = FileExists("secondary-privkey-enc.txt") && FileExists("secondary-pubkey.txt");
	bool hasEdSecondary = FileExists("secondary-ed25519-privkey-enc.txt") && FileExists("secondary-ed25519-pubkey.txt");

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

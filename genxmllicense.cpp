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
using namespace CryptoPP;

string SignLicense(AutoSeededRandomPool &rng, string strContents, string pass)
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
	string infoSig = SignLicense(rng, serialisedInfo, pass);

	//Encode as xml
	string xml="<license>";
	xml.append("<info>");
	xml.append(serialisedInfo);
	xml.append("</info>");
	xml.append("<infosig>");
	xml.append(infoSig);
	xml.append("</infosig>");
	xml.append("<key>");
	xml.append(GetFileContent("secondary-pubkey.txt"));
	xml.append("</key>");
	xml.append("<keysig>");
	xml.append(GetFileContent("secondary-pubkey-sig.txt"));
	xml.append("</keysig>");
	xml.append("</license>");
	
	//cout << xml << endl;

	ofstream out("xmllicense.xml");
	out << xml;
}



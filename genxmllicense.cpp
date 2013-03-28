//g++ genxmllicense.cpp -lcrypto++ -o genxmllicense

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
using namespace CryptoPP;

string SignLicense(AutoSeededRandomPool &rng, string strContents)
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
	string out;
	Base64Encoder enc(new StringSink(out));
	enc.Put(sbbSignature, sbbSignature.size());
	enc.MessageEnd();

	return out;
}

string SerialiseKeyPairs(vector<vector<std::string> > &info)
{
	string out;
	for(unsigned int pairNum = 0;pairNum < info.size();pairNum++)
	{
		out.append("<data k=\"");
		out.append(info[pairNum][0]);
		out.append("\" v=\"");
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
	string infoSig = SignLicense(rng, serialisedInfo);

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



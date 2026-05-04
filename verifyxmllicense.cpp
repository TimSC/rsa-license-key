// Verify an XML license and its embedded secondary key chain using the detected signature type.
//g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense

#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <fstream>
using namespace std;
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/xed25519.h>
using namespace CryptoPP;

string ComputeKeyId(const string& pubKeyBase64)
{
	string rawKey;
	StringSource(pubKeyBase64, true, new Base64Decoder(new StringSink(rawKey)));
	string digest;
	SHA256 hash;
	StringSource(rawKey, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
	return digest;
}

bool IsKeyRevoked(const string& keyId)
{
	ifstream f("revoked-keys.txt");
	if (!f.good()) return false;
	string line;
	while (getline(f, line))
	{
		if (!line.empty() && line.back() == '\r')
			line.pop_back();
		if (line == keyId) return true;
	}
	return false;
}

vector<vector<string> > ParseInfo(xmlNode *el)
{
	vector<vector<string> > info;
	if (el == NULL) return info;

	for (xmlNode *el2 = el->children; el2; el2 = el2->next)
	{			
		if (el2->type != XML_ELEMENT_NODE) continue;

		xmlChar *key = xmlGetProp(el2, (const xmlChar *)"k");
		xmlChar *value = xmlGetProp(el2, (const xmlChar *)"v");
		if (key == NULL || value == NULL)
		{
			if (key != NULL) xmlFree(key);
			if (value != NULL) xmlFree(value);
			continue;
		}

		vector<string> pair;
		pair.push_back((const char *)key);
		pair.push_back((const char *)value);
		info.push_back(pair);

		xmlFree(key);
		xmlFree(value);
	}

	return info;
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

int VerifyLicense(string signedTxt, string sigIn, string pubKeyEnc)
{
	try
	{
		//Read public key
		CryptoPP::ByteQueue bytes;
		StringSource file(pubKeyEnc, true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		RSA::PublicKey pubKey;
		pubKey.Load(bytes);

		RSASS<PSS, SHA256>::Verifier verifier(pubKey);

		//Read signed message
		string sigStr;
		StringSource sigFile(sigIn, true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		//Verify signature
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
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

int VerifyEd25519License(string signedTxt, string sigIn, string pubKeyEnc)
{
	try
	{
		CryptoPP::ByteQueue bytes;
		StringSource file(pubKeyEnc, true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		ed25519PublicKey pubKey;
		pubKey.Load(bytes);

		ed25519::Verifier verifier(pubKey);

		string sigStr;
		StringSource sigFile(sigIn, true, new Base64Decoder(new StringSink(sigStr)));

		string combined(signedTxt);
		combined.append(sigStr);

		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
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

string GetFileContent(string filename)
{
	ifstream fi(filename.c_str());
	if(!fi)
	{
		throw runtime_error("Could not open file");
	}

    // get length of file:
    fi.seekg (0, fi.end);
    int length = fi.tellg();
    fi.seekg (0, fi.beg);

	stringstream test;
	test << fi.rdbuf();

	return test.str();
}

int Verify(const char *filename)
{
	//parse the file and get the DOM 
	xmlDoc *doc = xmlReadFile(filename, NULL, XML_PARSE_NONET);

	if (doc == NULL)
	{
		cout << "error: could not parse file" << endl;
		return 0;
	}

	//Get the root element node
	xmlNode *root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL)
	{
		cout << "error: empty xml document" << endl;
		xmlFreeDoc(doc);
		return 0;
	}

	map<string, string> data;
	vector<vector<string> > info;

	//Iterate over xml elements
	for (xmlNode *rootEl = root_element; rootEl; rootEl = rootEl->next)
	{
		if (rootEl->type != XML_ELEMENT_NODE) continue;
		for (xmlNode *el = rootEl->children; el; el = el->next)
		{
			if(el->type != XML_ELEMENT_NODE) continue;
			//cout << "node type: Element, name: "<< el->name << endl;
			if(string((const char*)el->name) == string("info"))
			{
				info = ParseInfo(el);
			}
			else
			{
				xmlChar* value = xmlNodeListGetString(el->doc, el->children, 1);
				if (value != NULL)
				{
					data[(char *)el->name] = (char *)value;
					xmlFree(value);
				}
				else
				{
					data[(char *)el->name] = "";
				}
			}
		}
	}

	//Print found elements
	cout << SerialiseKeyPairs(info) << endl;
	map<string, string>::iterator it;
	for(it = data.begin(); it != data.end(); it++)
	{
		cout << it->first << endl;
	}

	bool hasRsaLicense = data.find("infosig") != data.end() &&
		data.find("key") != data.end() &&
		data.find("keysig") != data.end();
	bool hasEdLicense = data.find("edinfosig") != data.end() &&
		data.find("edkey") != data.end() &&
		data.find("edkeysig") != data.end();

	if (hasRsaLicense == hasEdLicense)
	{
		cout << "error: expected exactly one license signature type" << endl;
		xmlFreeDoc(doc);
		return 0;
	}

	string masterPubKey;
	try
	{
		if (hasEdLicense)
		{
			masterPubKey = GetFileContent("master-ed25519-pubkey.txt");
		}
		else
		{
			masterPubKey = GetFileContent("master-pubkey.txt");
		}
	}
	catch(std::exception &err)
	{
		cout << err.what() << endl;
		xmlFreeDoc(doc);
		return 0;
	}

	string serialisedInfo = SerialiseKeyPairs(info);
	int infoRet;
	int keyRet;
	if (hasEdLicense)
	{
		infoRet = VerifyEd25519License(serialisedInfo, data["edinfosig"], data["edkey"]);
		keyRet = VerifyEd25519License(data["edkey"], data["edkeysig"], masterPubKey);
		cout << "Info Ed25519 signature ret:" << infoRet << endl;
		cout << "Key Ed25519 signature ret:" << keyRet << endl;
	}
	else
	{
		infoRet = VerifyLicense(serialisedInfo, data["infosig"], data["key"]);
		keyRet = VerifyLicense(data["key"], data["keysig"], masterPubKey);
		cout << "Info RSA-PSS signature ret:" << infoRet << endl;
		cout << "Key RSA-PSS signature ret:" << keyRet << endl;
	}

	string keyContent = hasEdLicense ? data["edkey"] : data["key"];
	string keyId = ComputeKeyId(keyContent);
	int revRet = 1;
	if (IsKeyRevoked(keyId))
	{
		cout << "Key revoked: " << keyId << endl;
		revRet = 0;
	}

	//free the document
	xmlFreeDoc(doc);

	return infoRet && keyRet && revRet;

}


int main(int argc, char **argv)
{
	const char *filename = "xmllicense.xml";
	if (argc > 1)
	{
		filename = argv[1];
	}

	return Verify(filename) ? 0 : 1;

}

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
using namespace CryptoPP;

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

		RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

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

	if (data.find("infosig") == data.end() ||
		data.find("key") == data.end() ||
		data.find("keysig") == data.end())
	{
		cout << "error: license is missing required signature fields" << endl;
		xmlFreeDoc(doc);
		return 0;
	}

	string masterPubKey;
	try
	{
		masterPubKey = GetFileContent("master-pubkey.txt");
	}
	catch(std::exception &err)
	{
		cout << err.what() << endl;
		xmlFreeDoc(doc);
		return 0;
	}

	string serialisedInfo = SerialiseKeyPairs(info);
	int infoRet = VerifyLicense(serialisedInfo, data["infosig"], data["key"]);
	int keyRet = VerifyLicense(data["key"], data["keysig"], masterPubKey);
	cout << "Info signature ret:" << infoRet << endl;
	cout << "Key signature ret:" << keyRet << endl;

	//free the document
	xmlFreeDoc(doc);

	return infoRet && keyRet;

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

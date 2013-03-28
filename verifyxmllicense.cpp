//g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense

#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <stdexcept>
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
	for (xmlNode *el2 = el->children; el2; el2 = el2->next)
	{			
		map<string, string> data;
		if (el2->type != XML_ELEMENT_NODE) continue;
		xmlElement *el2t = (xmlElement *)el2;
		xmlAttribute *attributes = el2t->attributes;
		unsigned int i=0;
		xmlAttribute *attr = &attributes[i];
		while(attr!=NULL)
		{
			xmlChar* value = xmlNodeListGetString(el2t->doc, attr->children, 1);
			data[(const char *)attr->name] = (const char *)value;
			xmlFree(value);
			attr = (xmlAttribute *)attr->next;
		}

		vector<string> pair;
		pair.push_back(data["k"]);
		pair.push_back(data["v"]);
		info.push_back(pair);
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
	//Read public key
	CryptoPP::ByteQueue bytes;
	StringSource file(pubKeyEnc, true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PublicKey pubKey;
	pubKey.Load(bytes);

	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

	//Read signed message
	CryptoPP::ByteQueue sig;
	StringSource sigFile(sigIn, true, new Base64Decoder);
	string sigStr;
	StringSink sigStrSink(sigStr);
	sigFile.TransferTo(sigStrSink);

	string combined(signedTxt);
	combined.append(sigStr);

	//Verify signature
	try
	{
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
	return 1;
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

int Verify(const char *filename)
{
	//parse the file and get the DOM 
	xmlDoc *doc = xmlReadFile(filename, NULL, 0);

	if (doc == NULL)
	{
		cout << "error: could not parse file" << endl;
		return 0;
	}

	//Get the root element node
	xmlNode *root_element = xmlDocGetRootElement(doc);
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
				data[(char *)el->name] = (char *)value;
				xmlFree(value);
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

	string masterPubKey = GetFileContent("master-pubkey.txt");
	

	cout << "Info signature ret:" << VerifyLicense(SerialiseKeyPairs(info), data["infosig"], data["key"]) << endl;
	cout << "Key signature ret:" << VerifyLicense(data["key"], data["keysig"], masterPubKey) << endl;

	//free the document
	xmlFreeDoc(doc);

	return 1;

}


int main()
{

	Verify("xmllicense.xml");

}

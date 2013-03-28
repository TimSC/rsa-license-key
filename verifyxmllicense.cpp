//g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense

#include <iostream>
#include <map>
#include <vector>
using namespace std;
#include <libxml/parser.h>
#include <libxml/tree.h>

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

	for (xmlNode *rootEl = root_element; rootEl; rootEl = rootEl->next)
	{
		if (rootEl->type != XML_ELEMENT_NODE) continue;
		cout << "node type: Element, name: "<< rootEl->name << endl;

		map<string, string> data;
		vector<vector<string> > info;

		for (xmlNode *el = rootEl->children; el; el = el->next)
		{
			if(el->type != XML_ELEMENT_NODE) continue;
			cout << "node type: Element, name: "<< el->name << endl;
			if(string((const char*)el->name) == string("info"))
			{
				info = ParseInfo(el);
				cout << SerialiseKeyPairs(info) << endl;
			}
			else
			{
				xmlChar* value = xmlNodeListGetString(el->doc, el->children, 1);
				data[(char *)el->name] = (char *)value;
				xmlFree(value);
			}


		}
	}

	//free the document
	xmlFreeDoc(doc);

	return 1;

}


int main()
{

	Verify("xmllicense.xml");

}

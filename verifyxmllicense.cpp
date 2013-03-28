//g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>


int Verify(const char *filename)
{
	//parse the file and get the DOM 
	xmlDoc *doc = xmlReadFile(filename, NULL, 0);

	if (doc == NULL)
	{
		printf("error: could not parse file\n");
		return 0;
	}

	//Get the root element node
	xmlNode *root_element = xmlDocGetRootElement(doc);

	for (xmlNode *rootEl = root_element; rootEl; rootEl = rootEl->next)
	{
		if (rootEl->type != XML_ELEMENT_NODE) continue;
		printf("node type: Element, name: %s\n", rootEl->name);

		for (xmlNode *el = rootEl->children; el; el = el->next)
		{
			if (el->type != XML_ELEMENT_NODE) continue;
			printf("node type: Element, name: %s\n", el->name);

			for (xmlNode *el2 = el->children; el2; el2 = el2->next)
			{			
				if (el2->type != XML_ELEMENT_NODE) continue;
				printf("node type: Element, name: %s\n", el2->name);

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

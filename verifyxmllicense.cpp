//g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

int main()
{

    xmlDocPtr doc = xmlReadFile("xmllicense.xml", NULL, 0);
    if (doc == NULL) 
	{
        fprintf(stderr, "Failed to parse xmllicense.xml");
		exit(0);
    }
    xmlFreeDoc(doc);

    //Cleanup function for the XML library.
    xmlCleanupParser();
    
	//this is to debug memory for regression tests
    xmlMemoryDump();

}

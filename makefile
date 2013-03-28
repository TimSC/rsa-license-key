all:
	g++ genlicense.cpp -lcrypto++ -o genlicense
	g++ genmasterpair.cpp -lcrypto++ -o genmasterpair
	g++ gensecondarypair.cpp -lcrypto++ -o gensecondarypair
	g++ verifylicense.cpp -lcrypto++ -o verifylicense
	g++ genxmllicense.cpp -lcrypto++ -o genxmllicense
	g++ -I/usr/include/libxml2 verifyxmllicense.cpp -lcrypto++ -lxml2 -o verifyxmllicense


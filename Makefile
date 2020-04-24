test: test.cpp client.hpp
	g++ -g test.cpp -lssl -lcrypto -o test

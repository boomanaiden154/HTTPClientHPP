#include "client.hpp"
#include <iostream>

int main()
{
    std::cout << HTTPClient::getFile("http://neverssl.com") << std::endl;
    return 0;
}

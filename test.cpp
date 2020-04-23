#include "client.hpp"
#include <iostream>

int main()
{
    HTTPClient::getFile("http://neverssl.com/");
    return 0;
}

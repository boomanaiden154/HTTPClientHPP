#include "client.hpp"
#include <iostream>

int main()
{
    std::string test = HTTPClient::getFile("https://postman-echo.com/stream/5");
    //std::cout << HTTPClient::getFile("http://neverssl.com/");
    std::cout << test << std::endl;
    return 0;
}

#include "client.hpp"
#include <iostream>

int main()
{
    std::cout << HTTPClient::getFile("https://postman-echo.com/stream/5") << std::endl;
    return 0;
}

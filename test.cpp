#include "client.hpp"
#include <iostream>

int main(int argc, char** args)
{
    std::cout << HTTPClient::getFile(args[1]).body << std::endl;
}

#include "client.hpp"
#include <iostream>

int main()
{
    //std::cout << HTTPClient::getFile("https://postman-echo.com/stream/5").body << std::endl;
    struct HTTPClient::uri uri = HTTPClient::parseURI("https://media.discordapp.net/attachments/670160217966903296/754487595937038346/image0.png");
    std::cout << uri.protocol << std::endl;
    std::cout << uri.domain << std::endl;
    std::cout << uri.path << std::endl;
    std::vector<std::string> pathParts = HTTPClient::parsePath(uri.path);
    for(int i = 0; i < pathParts.size(); i++)
    {
        std::cout << pathParts[i] << std::endl;
    }
    return 0;
}

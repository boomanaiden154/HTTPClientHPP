#pragma once

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <openssl/ssl.h>

#define BUFFERSIZE 8192

class HTTPHeader
{
public:
    std::multimap<std::string, std::string> headers;
    bool isRequest;
    std::string headerField1;
    std::string headerField2;
    std::string headerField3;
    std::string body;
    //parser state, so that if the header is in multiple packets it can still be parsed
    std::string buffer;
    int bufferIndex;
    std::string fieldName;
    std::string fieldValue;
    bool parsingFieldName;
    bool parsingHeader;

    std::string requestType()
    {
        return headerField1;
    }

    std::string path()
    {
        return headerField2;
    }

    std::string protocol()
    {
        if(isRequest)
        {
            return headerField3;
        }
        else
        {
            return headerField1;
        }
    }

    void setProtocol(std::string toSet)
    {
        if(isRequest)
        {
            headerField3 = toSet;
        }
        else
        {
            headerField1 = toSet;
        }
    }

    std::string statusCode()
    {
        return headerField2;
    }

    void setStatusCode(std::string toSet)
    {
        headerField2 = toSet;
    }

    std::string status()
    {
        return headerField3;
    }

    void setStatus(std::string toSet)
    {
        headerField3 = toSet;
    }

    HTTPHeader(bool isRequest_ = false)
    {
        bufferIndex = 0;
        parsingFieldName = true;
        isRequest = isRequest_;
        parsingHeader = true;
    }

    void parse(std::string input)
    {
        if(parsingHeader)
        {
            buffer += input;
            if(bufferIndex == 0)
            {
                while(buffer[bufferIndex] != ' ')
                {
                    headerField1 += buffer[bufferIndex];
                    bufferIndex++;
                }
                bufferIndex++;
                while(buffer[bufferIndex] != ' ')
                {
                    headerField2 += buffer[bufferIndex];
                    bufferIndex++;
                }
                bufferIndex++;
                while(buffer[bufferIndex] != '\r')
                {
                    headerField3 += buffer[bufferIndex];
                    bufferIndex++;
                }
                bufferIndex += 2;
            }
            while(buffer[bufferIndex] != '\r' && buffer[bufferIndex + 1] != '\n')
            {
                if(parsingFieldName)
                {
                    while(buffer[bufferIndex] != ':' && buffer[bufferIndex + 1] != ' ')
                    {
                        fieldName += buffer[bufferIndex];
                        bufferIndex++;
                    }
                    bufferIndex += 2;
                    parsingFieldName = false;
                }
                else
                {
                    while(buffer[bufferIndex] != '\r' && buffer[bufferIndex + 1] != '\n')
                    {
                        fieldValue += buffer[bufferIndex];
                        bufferIndex++;
                    }
                    bufferIndex += 2;
                    headers.insert(std::pair<std::string,std::string>(fieldName,fieldValue));
                    fieldName.clear();
                    fieldValue.clear();
                    parsingFieldName = true;
                }
            }
            bufferIndex += 2; //for final \r\n
            body += buffer.substr(bufferIndex, buffer.size() - bufferIndex);
            parsingHeader = false;
        }
        else
        {
            body += input;
        }
    }

    std::string getHeaderString()
    {
        std::string toReturn;
        if(headerField1.size() != 0 && headerField2.size() != 0 && headerField3.size() != 0)
        {
                toReturn += headerField1 + " " + headerField2 + " " + headerField3 + "\r\n";
        }
        std::map<std::string, std::string>::iterator itr;
        for(itr = headers.begin(); itr != headers.end(); itr++)
        {
            toReturn += itr->first + ": " + itr->second + "\r\n";
        }
        if(toReturn.size() != 0)
        {
                toReturn += "\r\n";
        }
        toReturn += body;
        return toReturn;
    }
};

class HTTPClient
{
public:
    struct uri
    {
        std::string protocol;
        std::string domain;
        std::string path;
        int port;
    };

    static struct uri parseURI(std::string uri)
    {
        struct uri toReturn;
        toReturn.port = -1;
        int index = 0;
        while(uri[index] != ':')
        {
            toReturn.protocol += uri[index];
            index++;
        }
        index += 3;
        while(uri[index] != ':' && uri[index] != '/' && index < uri.size())
        {
            toReturn.domain += uri[index];
            index++;
        }
        if(uri[index] == ':')
        {
            index++;
            std::string portTemp;
            while(uri[index] != '/' && index < uri.size())
            {
                portTemp += uri[index];
                index++;
            }
            toReturn.port = std::stoi(portTemp);
        }
        else
        {
            if(toReturn.protocol == "http")
            {
                toReturn.port = 80;
            }
            else if(toReturn.protocol == "https")
            {
                toReturn.port = 443;
            }
        }
        while(index < uri.size())
        {
            toReturn.path += uri[index];
            index++;
        }
        return toReturn;
    }

    static int initalizeSocket(std::string address, int port)
    {
        int sockfd;

        struct addrinfo hints;
        struct addrinfo* servinfo;
        struct addrinfo* p;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        getaddrinfo(address.c_str(), std::to_string(port).c_str(), &hints, &servinfo);

        for(p = servinfo; p != NULL; p = p->ai_next)
        {
            if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            {
                continue;
            }
            if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                close(sockfd);
                continue;
            }
            break;
        }

        if(p == NULL)
        {
            return -1;
        }

        freeaddrinfo(servinfo);

        return sockfd;
    }

    static std::string getFile(std::string uri)
    {
        struct uri websiteURI = parseURI(uri);
        int port = websiteURI.port == -1 ? 80 : websiteURI.port;
        int sockfd = initalizeSocket(websiteURI.domain, port);
        std::string path = websiteURI.path == "" ? "/" : websiteURI.path;

        HTTPHeader request(true);
        request.headerField1 = "GET";
        request.headerField2 = "/";
        request.headerField3 = "HTTP/1.1";

        request.headers.insert(std::pair<std::string,std::string>("Host",websiteURI.domain));
        request.headers.insert(std::pair<std::string,std::string>("User-Agent","custom/0.0.1"));
        request.headers.insert(std::pair<std::string,std::string>("Accept","*/*"));

        std::string headerString = request.getHeaderString();

        bool ssl = websiteURI.protocol == "https";

        //init SSL
        SSL_CTX* ssl_ctx;
        SSL* conn = SSL_new(ssl_ctx);
        if(ssl)
        {
            SSL_load_error_strings();
            SSL_library_init();
            ssl_ctx = SSL_CTX_new(SSLv23_client_method());

            conn = SSL_new(ssl_ctx);
            SSL_set_fd(conn, sockfd);

            SSL_connect(conn);
        }

        if(ssl)
        {
            SSL_write(conn, headerString.c_str(), headerString.size());
        }
        else
        {
            send(sockfd, headerString.c_str(), headerString.size(), 0);
        }

        HTTPHeader response;

        char headerBuffer[8192];

        int headerRecieved;
        if(ssl)
        {
            headerRecieved = SSL_read(conn, headerBuffer, 8191);
        }
        else
        {
            headerRecieved = recv(sockfd, headerBuffer, 8191, 0);
        }
        headerBuffer[headerRecieved + 1] = '\0';

        response.parse(std::string(headerBuffer));

        while(response.body.size() != std::stoi(response.headers.find("Content-Length")->second))
        {
            char buffer[8192];
            int recieved;
            if(ssl)
            {
                recieved = SSL_read(conn, buffer, 8191);
            }
            else
            {
                recieved = recv(sockfd, buffer, 8191, 0);
            }
            buffer[recieved + 1] = '\0';
            response.parse(std::string(buffer));
        }

        return response.body;
    }
};

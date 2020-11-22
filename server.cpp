#include "servClient.h"
#include "server.h"
#include <iostream>
#include <string>
#include <vector>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)

const int PACKET_TYPE_LENGHT = 5;

const int MAX_CLIENT_AMOUNT = 100;

const char *MSG_PCKT = "/000/";
const char *REG_PCKT = "/111/";
const char *DISCONNECT_PCKT = "/222/";

std::vector<Client*> clients;
int userAmount;

void clientHandler(Client *currentClient)
{
    char msgLen[5] = {};
    char* msg;
    while (true) 
    {
            recv(currentClient->socket, msgLen, 4, NULL);
            int len = std::stoi(msgLen);
            msg = (char*)calloc(len + 1, sizeof(char));
            recv(currentClient->socket, msg, len, NULL);
            packetHandle(msg, currentClient);
            free(msg);
    }
}

void packetHandle(char* _msg, Client *currentClient)
{
    std::string packet(_msg);
    std::string packetType = packet.substr(0, PACKET_TYPE_LENGHT);
    std::string msg = packet.substr(PACKET_TYPE_LENGHT, packet.length() - PACKET_TYPE_LENGHT);
    if (!packetType.compare(MSG_PCKT))
    {
        msg = "" + currentClient->name + ": " + msg;
        for (int i = 0; i < clients.size(); i++)
        {
            if (clients[i] == currentClient)
                continue;
            sendPacket(clients[i]->socket, msg);
        }
    }
    else if (!packetType.compare(REG_PCKT))
    {
        currentClient->name = msg;
        //TODO: Everybody recv massage about someone connection
        std::cout << "Added   - " << msg << std::endl;
    }
    else if (!packetType.compare(DISCONNECT_PCKT))
    {
        closesocket(currentClient->socket);
        std::cout << "Deleted - " << currentClient->name << std::endl;
        auto it = find(clients.begin(), clients.end(), currentClient);
        clients.erase(clients.begin() + distance(clients.begin(), it));
        userAmount--;
        delete currentClient;
        free(_msg);
        ExitThread(0);
    }
}

void sendPacket(SOCKET client, const std::string &packet) 
{
    std::string msg = std::to_string(packet.length());
    send(client, msg.c_str(), 4, NULL);
    send(client, packet.c_str(), packet.length(), NULL);
}

int main()
{
    WORD DLLVersion = MAKEWORD(2, 1);
    WSADATA wsadata;
    if (WSAStartup(DLLVersion, &wsadata) != 0)
    {
        std::cout << "Error" << std::endl;
        exit(1);
    }

    SOCKADDR_IN addr;
    int size = sizeof(addr);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(1111);
    addr.sin_family = AF_INET;

    SOCKET listener = socket(AF_INET, SOCK_STREAM, NULL);
    if (bind(listener, (SOCKADDR*)&addr, size))
    {
        std::cout << "BIND ERROR" << std::endl;
        exit(2);
    }
    listen(listener, SOMAXCONN);
    SOCKET clientSock;
    while (true) 
    {
        std::cout << "lox1" << std::endl;
        clientSock = accept(listener, (SOCKADDR*)&addr, &size);
        std::cout << "lox" << std::endl;
        if (clientSock == 0)
        {
            std::cout << "Connection failed" << std::endl;
        }
        else
        {
            Client *newClient = new Client(clientSock);
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)clientHandler, (LPVOID)(newClient), NULL, NULL);
            clients.push_back(newClient);
            userAmount++;
        }
    }
}
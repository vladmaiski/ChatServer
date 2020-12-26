#pragma once
void clientHandler(Client* currentClient);
void packetHandle(char* _msg, Client* currentClient);
void sendPacket(SOCKET client, const std::string& packet);
void sendUsersInfo();
bool checkOnline(std::string name);
void disconnectUser(Client* currentClient);
bool checkLen(std::string msg, int maxSize);
std::string censure(std::string msg);
bool isNameValid(std::string name);
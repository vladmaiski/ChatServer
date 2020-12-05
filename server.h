#pragma once
void clientHandler(Client* currentClient);
void packetHandle(char* _msg, Client* currentClient);
void sendPacket(SOCKET client, const std::string& packet);
void sendUsersInfo();
bool checkOnline(std::string name);
void disconnectUser(Client* currentClient);
char generatePrivateKey();
std::string crypt(std::string msg, char key);
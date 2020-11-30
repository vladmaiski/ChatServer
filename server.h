#pragma once
void clientHandler(Client* currentClient);
void packetHandle(char* _msg, Client* currentClient);
void sendPacket(SOCKET client, const std::string& packet);
void sendUsersInfo();
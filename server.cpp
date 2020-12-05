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

const char* FILE_PATH = "UserDB.txt";

const char* SERVER_IP = "127.0.0.1";
const short DEFAULT_PORT = 1111;

const char* MSG_PCKT = "/000/";
const char* LOG_PCKT = "/111/";
const char* DISCONNECT_PCKT = "/222/";
const char* REGISTRATION_PCKT = "/333/";
const char* USER_REGISTRED_PCKT = "/444/";
const char* USER_NOT_REGISTRED_PCKT = "/555/";
const char* NOT_LOGGED_PCKT = "/666/";
const char* LOGGED_PCKT = "/777/";
const char* USER_INFO_PCKT = "/888/";
const char* PRIVATE_MSG = "/999/";

std::vector<Client*> clients;
int userAmount;

void clientHandler(Client* currentClient)
{
	currentClient->privateKey = generatePrivateKey();
	std::string msgKey(std::to_string(currentClient->privateKey));
	send(currentClient->socket, msgKey.c_str(), PACKET_TYPE_LENGHT, NULL);

	char msgLen[5] = {};
	char* msg;
	while (true)
	{
		try {
			recv(currentClient->socket, msgLen, 4, NULL);
			int len = std::stoi(msgLen);
			if (len >= PACKET_TYPE_LENGHT)
			{
				msg = (char*)calloc(len + 1, sizeof(char));
				recv(currentClient->socket, msg, len, NULL);
				packetHandle(msg, currentClient);
			}
		}
		catch (...) {
			std::cout << "Exception" << std::endl;
			disconnectUser(currentClient);
			ExitThread(1);
		}
		//free(msg);
	}
}

bool regUser(std::string& name, std::string& password) {
	FILE* database = fopen(FILE_PATH, "a+");
	char userName[11];
	char userPassword[11];
	bool isRegistred = true;
	while (fscanf(database, "%s %s", userName, userPassword) != EOF) {
		if (!name.compare(userName))
			isRegistred = false;
	}
	fprintf(database, "%s %s\n", name.c_str(), password.c_str());
	fclose(database);
	return isRegistred;
}


bool verifyUser(std::string& name, std::string& password) {
	FILE* database = fopen(FILE_PATH, "a+");
	char userName[11];
	char userPassword[11];
	while (fscanf(database, "%s %s", userName, userPassword) != EOF) {
		if (!name.compare(userName) && !password.compare(userPassword))
			return true;
	}
	fclose(database);
	return false;
}

std::string crypt(std::string msg, char key)
{
	std::string encryptedMsg;
	for (int i = 0; i < msg.size(); i++) {
		encryptedMsg += msg[i] ^ key;
	}
	return encryptedMsg;
}

void packetHandle(char* _msg, Client* currentClient)
{
	std::string packet(_msg);
	std::string packetType = packet.substr(0, PACKET_TYPE_LENGHT);
	int msgLen = packet.length() - PACKET_TYPE_LENGHT;
	std::string msg = packet.substr(PACKET_TYPE_LENGHT, msgLen);

	std::string userPassword = "";
	std::string userLogin = "";
	if (!packetType.compare(REGISTRATION_PCKT) || !packetType.compare(LOG_PCKT))
	{
		int index = 0;
		while (index < msg.size())
		{
			if (msg[index] == ':')
			{
				for (int i = index + 1; i < msg.size(); i++)
				{
					userPassword += msg[i];
				}
				break;
			}
			userLogin += msg[index];
			index++;
		}
	}

	if (!packetType.compare(REGISTRATION_PCKT))
	{
		if(regUser(userLogin, userPassword))
		{
			send(currentClient->socket, USER_REGISTRED_PCKT, PACKET_TYPE_LENGHT, NULL);
		}
		else
		{
			send(currentClient->socket, USER_NOT_REGISTRED_PCKT, PACKET_TYPE_LENGHT, NULL);
		}
		return;
	}

	if (!packetType.compare(DISCONNECT_PCKT))
	{
		disconnectUser(currentClient);

		delete currentClient;
		free(_msg);
		ExitThread(0);
		return;
	}

	if (!packetType.compare(LOG_PCKT))
	{
		if (verifyUser(userLogin, userPassword) && !checkOnline(userLogin))
		{
			currentClient->name = userLogin;
			std::cout << "Added   - " << userLogin << std::endl;
			currentClient->isAuth = true;
			send(currentClient->socket, LOGGED_PCKT, PACKET_TYPE_LENGHT, NULL);
			sendUsersInfo();
		} else
		{
			send(currentClient->socket, NOT_LOGGED_PCKT, PACKET_TYPE_LENGHT, NULL);
		}
	}


	if(currentClient->isAuth)
	{
		if (!packetType.compare(MSG_PCKT))
		{
			msg = MSG_PCKT + currentClient->name + ": " + msg;
			for (int i = 0; i < clients.size(); i++)
			{
				if (clients[i] == currentClient)
					continue;
				sendPacket(clients[i]->socket, msg);
			}
		}

		if (!packetType.compare(PRIVATE_MSG))
		{	
			//msg = crypt(msg, currentClient->privateKey);
			for (int i = 0; i < msg.size(); i++)
			{
				if (msg[i] == ':')
				{
					std::string reiceverName(msg.substr(0, i));
					msg = msg.substr(i + 1, msg.size() - i + 1);
					msg = PRIVATE_MSG + currentClient->name + ": " + msg;
					if(reiceverName.compare(currentClient->name))
					{
 						for (Client* client : clients)
						{
							if (!reiceverName.compare(client->name))
								sendPacket(client->socket, msg);
						}
					}
					break;
				}
			}
		}
	}
}

void disconnectUser(Client* currentClient)
{
	closesocket(currentClient->socket);
	if (currentClient->name != "")
		std::cout << "Deleted - " << currentClient->name << std::endl;
	auto it = find(clients.begin(), clients.end(), currentClient);
	clients.erase(clients.begin() + distance(clients.begin(), it));
	userAmount--;

	sendUsersInfo();
}

char generatePrivateKey()
{
		srand(time(0));
		char key = rand() % 10 + 1;
		return key;
}

bool checkOnline(std::string name)
{
	for (Client* client : clients)
	{
		if (!name.compare(client->name))
			return true;
	}
	return false;
}


void sendUsersInfo()
{
	std::string msg;
	msg += USER_INFO_PCKT;
	for (int i = 0; i < clients.size(); i++)
	{
		if (clients[i]->isAuth)
		{
			msg += clients[i]->name;
			msg += ":";
		}
	}
	for (Client* client : clients)
	{
		if (client->isAuth == true)
			sendPacket(client->socket, msg);
	}
}


void sendPacket(SOCKET client, const std::string& packet)
{
	std::string msg = std::to_string(packet.length());
	send(client, msg.c_str(), 4, NULL);
	send(client, packet.c_str(), packet.length(), NULL);
}

void startupWSA()
{
	WORD DLLVersion = MAKEWORD(2, 1);
	WSADATA wsadata;
	if (WSAStartup(DLLVersion, &wsadata) != 0)
	{
		std::cout << "Error" << std::endl;
		exit(1);
	}
}

int main()
{
	FILE* database = fopen(FILE_PATH, "a+");
	startupWSA();
	SOCKADDR_IN addr;
	int size = sizeof(addr);
	addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	addr.sin_port = htons(DEFAULT_PORT);
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
		clientSock = accept(listener, (SOCKADDR*)&addr, &size);
		if (clientSock == 0)
		{
			std::cout << "Connection failed" << std::endl;
		}
		else
		{
			Client* newClient = new Client(clientSock);
			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)clientHandler, (LPVOID)(newClient), NULL, NULL);
			clients.push_back(newClient);
			userAmount++;
		}
	}
}
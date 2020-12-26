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

const int MAX_NAME_LEN = 30;

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

const std::string CENSURE_SERV_PORT("8090");

std::vector<Client*> clients;
SOCKET censureServer;

int userAmount;

void clientHandler(Client* currentClient)
{
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
		if(isNameValid(userLogin) && regUser(userLogin, userPassword))
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
		if (isNameValid(userLogin) && verifyUser(userLogin, userPassword) && !checkOnline(userLogin))
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
			msg = censure(msg);
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
			for (int i = 0; i < msg.size(); i++)
			{
				if (msg[i] == ':')
				{
					std::string reiceverName(msg.substr(0, i));
					msg = msg.substr(i + 1, msg.size() - i + 1);
					msg = censure(msg);
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

bool isNameValid(std::string name)
{
	if (!checkLen(name, MAX_NAME_LEN))
		return false;
	for (const char c : name) {
		if (!isalpha(c) && !isdigit(c))
			return false;
	}

	return true;
}

bool checkLen(std::string msg, int maxSize)
{
	if (msg == "" || msg.length() > maxSize)
		return false;
	return true;
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
		if (clients[i]->isAuth == true)
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

bool connectToCensureServ()
{
	censureServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN servAddr;

	servAddr.sin_port = htons(8090);
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	
	if (connect(censureServer, (SOCKADDR*)(&servAddr), sizeof(servAddr)) != 0) {
		std::cout << "Could not connect to censure server";
		exit(1);
	}
}

std::string getAlternative(std::string character)
{
	const int len = 15;
	std::string unsaveChars[len] = { " ", "\"",
							 "<", ">", "#", "%", "{", "}", "|", "\\", "^", "~", "[", "]", "`" };
	std::string URLcode[len] = { "%20", "%22",
						 "%3c", "%3e", "%23", "%25", "%7b", "%7d", "%7c", "%5c", "%5e", "%7e", "%5b", "%5d", "%60" };
	std::string alternative;
	for (int i = 0; i < len; i++)
	{
		if (!unsaveChars[i].compare(character))
		{
			return URLcode[i];
		}
	}
	return character;
}

std::string prepareHTMLMsg(std::string msg)
{
	const char *HTML_SPACE = "%20";
	std::string htmlMsg;

	for(int i = 0; i < msg.size(); i++)
	{
		htmlMsg += getAlternative(std::string(1, msg[i]));
	}
	return htmlMsg;
}

std::string censure(std::string msg)
{
	if (!connectToCensureServ())
		return msg;

	int nDataLength;
	char buffer[10000];
	std::string websiteHTML = "GET /?text="+msg + "Connection: close";
	int lineCounter = 0;

	while ((nDataLength = recv(censureServer, buffer, 10000, 0)) > 0) {
		int i = 0;
		while (buffer[i] >= 32 || buffer[i] == '\n' || buffer[i] == '\r') {
			if (lineCounter > 5)
				websiteHTML += buffer[i];
			if (buffer[i] == '\n')
				lineCounter++;
			i += 1;
		}
	}

	return websiteHTML;
}

int main()
{
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
	std::cout << "Server started" << std::endl;
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
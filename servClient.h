#pragma once
#include "servClient.h"
#include <winsock2.h>
#include <string>

class Client
{
public:
	SOCKET socket;
	std::string name;
	bool isAuth;

	Client(SOCKET socket)
	{
		this->name = name;
		this->socket = socket;
	}

};
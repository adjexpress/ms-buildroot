#ifdef __linux__ 
#		include "../include/Server.h"
#		include "../include/Encryption.h"
#elif defined _WIN32
#		include "Server.h"
#		include "Encryption.h"
#endif

#include <stdlib.h>
#include <cstdlib>

Encryption* encryption {nullptr};

int main()
{
	//server_output_log.open("server_output_log.txt", std::ios::binary | std::ios::out);
	
	// A 256 bit key
	unsigned char key[] = {
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x61, 0x20, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x20,
		0x74, 0x65, 0x78, 0x74, 0x20, 0x66, 0x6F, 0x72, 
		0x20, 0x64, 0x65, 0x62, 0x75, 0x67, 0x65, 0x72 
	};


	// A 128 bit IV
	unsigned char iv[] = {
		0x48, 0x61, 0x76, 0x65, 0x20, 0x61, 0x20, 0x6E,
		0x69, 0x63, 0x65, 0x20, 0x64, 0x61, 0x79, 0x2E
	};

	Encryption encryption = { key, iv };

	int status = 0;

	Server server(TCP, 64000, &encryption);

	if ((status = server.CreateSocket()) < 0)
		return ~0;

	if ((status = server.BindSocket()) < 0)
		return ~0;

	if ((status = server.Listen(10)) < 0)
		return ~0;

	server.InfiniteAccept();

	server.ShutDown();

	return 0;
}



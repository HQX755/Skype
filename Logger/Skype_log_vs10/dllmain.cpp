#include "stdafx.h"
#include "Hooks.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"EZLib.lib")

EZ::CHook *g_Hook = new EZ::CHook();

#define SKYPE_LOOP_RECV 0x006CFDF0

#define SKYPE_RC4_CRYPT_TCP 0x00746FD0
#define SKYPE_RC4_CRYPT_UDP 0x00746F20

#define SKYPE_RSA 0x006B3F40
#define SKYPE_RSA_END 0x006B42DA
#define SKYPE_AES 0x006E97A0

void InitializeHooks() 
{
	if (g_Hook) 
	{
		RConnect			= (int(WSAAPI*)(SOCKET, const sockaddr*, int))
								g_Hook->PlaceHook((unsigned char*)&connect, &hkConnect);

		RRC4Crypt			= (void(*)(int))
								g_Hook->PlaceHook((unsigned char*)SKYPE_RC4_CRYPT_TCP, &hkRC4CryptBegin);

		RRC4ShortCryptBegin = (void(*)(char *, int))
								g_Hook->PlaceHook((unsigned char*)SKYPE_RC4_CRYPT_UDP, &hkRC4ShortCryptBegin);

		RCloseSocket		= (int(WSAAPI*)(SOCKET))
								g_Hook->PlaceHook((unsigned char*)&closesocket, &hkCloseSocket);

		RSend				= (int(WSAAPI*)(SOCKET, char*, int, int))
								g_Hook->PlaceHook((unsigned char*)&send, &hkSend);

		RSendTo				= (int(WSAAPI*)(SOCKET, char*, int, int, const sockaddr*, int))
								g_Hook->PlaceHook((unsigned char*)&sendto, &hkSendTo);

		RRecv				= (int(WSAAPI*)(SOCKET, char*, int, int))
								g_Hook->PlaceHook((unsigned char*)&recv, &hkRecv);

		RRecvFrom			= (int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int))
								g_Hook->PlaceHook((unsigned char*)&recvfrom, &hkRecvFrom);

		RRSACrypt			= (int(*)(char*, int, char*, char*))
								g_Hook->PlaceHook((unsigned char*)SKYPE_RSA, &hkRSACrypt);

		RAESCrypt			= (int(*)(char*, int, int, int, int, int))
								g_Hook->PlaceHook((unsigned char*)SKYPE_AES, &hkAESCrypt);

		//to get the buffer data on stack
		memset((void*)SKYPE_RSA_END, 0x90, 6);
		g_Hook->PlaceHook((void*)SKYPE_RSA_END, &hkRSAEnd);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_rAESon_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_rAESon_for_call)
	{
	case DLL_PROCESS_ATTACH:

		InitializeCriticalSection(g_LogMutex);

		g_Log = CreateEvent(nullptr, true, false, L"log");

		InitializeHooks();

		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:

		if (g_Hook) 
		{
			delete g_Hook;
			g_Hook = nullptr;
		}

		if (g_LogMutex)
		{
			DeleteCriticalSection(g_LogMutex);
			g_LogMutex = nullptr;
		}

		break;
	}
	return TRUE;
}


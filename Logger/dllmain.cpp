// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "hooks.h"

EZ::CHook *g_Hook = new EZ::CHook();

#define SKYPE_LOOP_RECV 0x006CFDF0

#define SKYPE_RC4_CRYPT_TCP 0x00746FD0
#define SKYPE_RC4_CRYPT_UDP 0x00746F20

#define SKYPE_RSA 0x006B3F40
#define SKYPE_EAS 0x006E97A0

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

		REASCrypt			= (int(*)(char*, int, int, int, int, int))
								g_Hook->PlaceHook((unsigned char*)SKYPE_EAS, &hkEASCrypt);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
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


#include "stdafx.h"
#include <Windows.h>

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <iomanip>

#include <WinSock2.h>

#include "Hook.h"

static long long	procId		= GetCurrentProcessId();
static std::string	filename	= std::string("Debug") + std::to_string(procId) + std::string(".txt");

int create_format(char *buffer, const char *f, bool add_thread_date)
{
	int len = 0;

	SYSTEMTIME st;
	GetSystemTime(&st);

	if (add_thread_date)
	{
		len = _snprintf(buffer, strlen("%02d:%02d - %02d:%02d T#%02d:"), "%02d:%02d - %02d:%02d T#%02d: ", 
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId());
	}

	strcpy(buffer + len, f);
	len += strlen(f);

	buffer[len] = '\0';

	return len;
}

extern HANDLE g_Log = nullptr;
extern LPCRITICAL_SECTION g_LogMutex = new CRITICAL_SECTION;

void enter_cs()
{
	while (!TryEnterCriticalSection(g_LogMutex))
	{
		WaitForSingleObject(g_LogMutex, INFINITE);
	}

	ResetEvent(g_Log);
}

void leave_cs()
{
	LeaveCriticalSection(g_LogMutex);
	SetEvent(g_Log);
}

void log_main_put(std::stringstream &ss, bool add_thread_date, bool enter)
{
	FILE *fp = nullptr;

	if (enter)
	{
		enter_cs();
	}

	do
	{
		fopen_s(&fp, filename.c_str(), "a+");
	} while (!fp);

	std::fputs(ss.str().c_str(), fp);

	fclose(fp);

	if (enter)
	{
		leave_cs();
	}
}

void log_main_put(const char *format, bool add_thread_date, bool enter, ...)
{
	static char buf[4096];
	FILE *fp = nullptr;

	if (enter)
	{
		enter_cs();
	}

	create_format(buf, format, add_thread_date);

	do
	{
		fopen_s(&fp, filename.c_str(), "a+");
	} while (!fp);

	__asm
	{
		mov ecx, 0
		mov ebx, 0
		mov esi, format
cont :
		mov al, byte ptr ss : [esi + ebx]
		cmp al, 0
		je go0
		cmp al, 25h
		je addx
		jmp cont0
addx :
		inc ecx
cont0 :
		inc ebx
		jmp cont
	}

go0:
	__asm
	{
		mov edi, ecx
	}
	
go:
	__asm
	{
		cmp ecx, 0
		je print
		mov ebx, dword ptr ss : [ebp + 16 + 4 * ecx]
		push ebx
		dec ecx
		jmp go
print :
		mov esi, esp
		lea eax, [buf]
		push eax
		mov eax, fp
		push eax
		call fprintf
		imul edi, 4
		add edi, 8
		add esp, edi
		cmp esi, esp
	}

	fclose(fp);

	if (enter)
	{
		leave_cs();
	}
}

void write_stream_data(char *buffer, int len, std::stringstream &ss)
{
	for (int i = 0; i < len; i += 16)
	{
		for (int j = 0; j < 16 && i + j < len; ++j)
		{
			ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (buffer[i + j] & 0xFF);
			ss << " ";
		}

		ss << "\n";
	}

	ss << "\0";
}

void log_print_data(char *buffer, int len)
{
	std::stringstream ss;

	if (len <= 0)
	{
		return;
	}

	write_stream_data(buffer, len, ss);
	log_main_put(ss, false, false);
}

class CSocketData
{
private:
	SOCKET m_socket;

	unsigned int		m_ip;
	unsigned short		m_port;
	unsigned int		m_bytesRecv;
	unsigned int		m_bytesSent;

public:
	SOCKET GetSocket()
	{
		return m_socket;
	}

public:
	CSocketData(SOCKET s, unsigned int ip, unsigned short port) : m_bytesRecv(0), m_bytesSent(0)
	{
		m_socket	= s;
		m_ip		= ip;
		m_port		= port;

		OnConnectSocket();
	}

	~CSocketData()
	{
		OnCloseSocket();
	}

	void OnCloseSocket()
	{
		unsigned int ip			= m_ip;
		unsigned short port		= m_port;

		log_main_put("Closed socket: ip: %u.%u.%u.%u:%u - Sent %d, Recvd %d\n", 
			true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port, m_bytesSent, m_bytesRecv);
	}

	void OnConnectSocket()
	{
		unsigned int ip			= m_ip;
		unsigned short port		= m_port;

		log_main_put("Connected socket: ip: %u.%u.%u.%u:%u\n", 
			true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port);
	}

	void OnSend(char *buffer, int len)
	{
		m_bytesSent += len;

		unsigned int ip			= m_ip;
		unsigned short port		= m_port;
		
		log_main_put("Sent tcp packet to %u.%u.%u.%u:%u - %d len\n", 
			true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port, len);

		log_print_data(buffer, len);
	}

	void OnRecv(char *buffer, int len)
	{
		m_bytesRecv += len;

		unsigned int ip			= m_ip;
		unsigned short port		= m_port;

		log_main_put("Recv tcp packet from %u.%u.%u.%u:%u - %d len\n", 
			true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port, len);

		log_print_data(buffer, len);
	}
};

class CSocketManager
{
private:
	std::vector<CSocketData*> m_vSocketData;

public:
	CSocketManager() {
	}

	CSocketData *operator[](SOCKET s) {
		for (unsigned int i = 0; i < m_vSocketData.size(); ++i)
		{
			if (m_vSocketData[i]->GetSocket() == s)
			{
				return m_vSocketData[i];
			}
		}

		return nullptr;
	}

	void Add(SOCKET s, sockaddr *addr) {
		sockaddr_in			*in;
		unsigned short		port;
		unsigned int		ip;

		in		= (sockaddr_in*)addr;
		ip		= in->sin_addr.S_un.S_addr;
		port	= in->sin_port;

		CSocketData *data = new CSocketData(s, ip, port);
		if (data) {
			m_vSocketData.push_back(data);
		}
	}

	bool Remove(SOCKET s) {
		for (unsigned i = 0; i < m_vSocketData.size(); ++i) {
			if (m_vSocketData[i]->GetSocket() == s) {
				m_vSocketData[i]->OnCloseSocket();

				m_vSocketData.erase(m_vSocketData.begin() + i);

				return true;
			}
		}

		return false;
	}
};

static CSocketManager SOCKETS;

int(WSAAPI*RRecvFrom)(SOCKET, char*, int, int, sockaddr*, int);
int WSAAPI hkRecvFrom(SOCKET s, char *buffer, int len, int flags, sockaddr *from, int fromlen)
{
	unsigned int		ip;
	unsigned short		port;
	sockaddr_in			*in;

	int recv = RRecvFrom(s, buffer, len, flags, from, fromlen);

	in = (sockaddr_in*)from;
	ip = in->sin_addr.S_un.S_addr;
	port = in->sin_port;

	if (recv != INVALID_SOCKET)
	{
		log_main_put("Recv packet from %u.%u.%u.%u:%u - %d len\n", true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port, min(recv, len));
		log_print_data(buffer, min(recv, len));
	}

	return recv;
}

int(WSAAPI*RSendTo)(SOCKET, char*, int, int, const sockaddr*, int);
int WSAAPI hkSendTo(SOCKET s, char *buffer, int len, int flags, const sockaddr* to, int tolen)
{
	unsigned int		ip;
	unsigned short		port;
	sockaddr_in			*in;

	int ret = RSendTo(s, buffer, len, flags, to, tolen);

	in		= (sockaddr_in*)to;
	ip		= in->sin_addr.S_un.S_addr;
	port	= in->sin_port;

	if (ret != INVALID_SOCKET)
	{
		log_main_put("Sent packet to %u.%u.%u.%u:%u - %d len\n", true, true, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24, port, ret);
		log_print_data(buffer, ret);
	}

	return ret;
}

int(WSAAPI*RRecv)(SOCKET, char*, int, int);
int WSAAPI hkRecv(SOCKET s, char *buffer, int len, int flags)
{
	int ret = RRecv(s, buffer, len, flags);

	CSocketData *sock = SOCKETS[s];
	if (sock)
	{
		sock->OnRecv(buffer, ret);
	}

	return ret;
}

int(WSAAPI*RSend)(SOCKET, char*, int, int);
int WSAAPI hkSend(SOCKET s, char *buffer, int len, int flags)
{
	CSocketData *sock = SOCKETS[s];
	if (sock)
	{
		sock->OnSend(buffer, len);
	}

	return RSend(s, buffer, len, flags);
}

int(WSAAPI*RConnect)(SOCKET, const sockaddr*, int);
int WSAAPI hkConnect(SOCKET s, const sockaddr *name, int len)
{
	SOCKETS.Add(s, const_cast<sockaddr*>(name));
	
	return RConnect(s,name,len);
}

int(__stdcall*RCloseSocket)(SOCKET);
int __stdcall hkCloseSocket(SOCKET s)
{
	SOCKETS.Remove(s);

	return RCloseSocket(s);
}

struct RC4s
{
	DWORD	dwThreadId;
	DWORD	dwLen;
	DWORD	dwRet;
	BYTE*	pData;
	
	std::stringstream encrypted, decrypted;
};

static std::vector<RC4s*> vRC4s;
static char *pLastCryptBuffer = nullptr;

RC4s* ThreadToRc4(unsigned long dwThreadId)
{
	for (unsigned int i = 0; i < vRC4s.size(); ++i)
	{
		if (vRC4s[i]->dwThreadId == dwThreadId) {
			return vRC4s[i];
		}
	}

	return nullptr;
}

void OnRC4CryptBegin(char *buf, int len)
{
	enter_cs();

	pLastCryptBuffer = buf;

	log_main_put("New RC4 dump: %d len\n", true, true, len);
	log_print_data(buf, len);
}

void OnRC4CryptEnd(char *buf, int len)
{
	if (pLastCryptBuffer != nullptr)
	{
		log_main_put("RC4 after:\n", false, true);
		log_print_data(pLastCryptBuffer, len);
	}

	leave_cs();
}

void OnRC4ShortCryptBegin(char *buf, int len, unsigned int ret)
{
	log_main_put("New RC4 short dump: %d len from %p\n", true, true, len, ret);
	log_print_data(buf, len);
}

void OnRC4ShortCryptEnd(char *buf, int len)
{
	log_main_put("RC4s after:\n", false, true);
	log_print_data(buf, len);
}

void(*RRC4Crypt)(int);

__declspec(naked) void hkRC4CryptBegin(int len)
{
	_asm pushad
	_asm push dword ptr ds : [esp + 24h]
	_asm push ecx
	_asm call OnRC4CryptBegin
	_asm pop ebp
	_asm pop ebp
	_asm popad
	_asm push ebp
	_asm mov ebp, esp
	_asm push len
	_asm call RRC4Crypt
	_asm add esp, 4
	_asm mov esp, ebp
	_asm pop ebp
	_asm pushad
	_asm push dword ptr ss : [esp + 2Ch]
	_asm push ecx
	_asm call OnRC4CryptEnd
	_asm pop ebp
	_asm pop ebp
	_asm popad
	_asm retn 4
}

void(*RRC4ShortCryptBegin)(char *data, int len);

__declspec(naked) void hkRC4ShortCryptBegin(char *data, int len)
{
	_asm pushad
	_asm push dword ptr ss : [esp + 20h]
	_asm push dword ptr ss : [esp + 2Ch]
	_asm push dword ptr ss : [esp + 2Ch]
	_asm call OnRC4ShortCryptBegin
	_asm pop ebp
	_asm pop ebp
	_asm pop ebp
	_asm popad
	_asm push ebp
	_asm mov ebp, esp
	_asm push len
	_asm push data
	_asm call RRC4ShortCryptBegin
	_asm add esp, 8
	_asm mov esp, ebp
	_asm pop ebp
	_asm pushad
	_asm push dword ptr ss : [esp + 28h]
	_asm push dword ptr ss : [esp + 28h]
	_asm call OnRC4ShortCryptEnd
	_asm pop ebp
	_asm pop ebp
	_asm popad
	_asm retn 8
}

__declspec(naked) void end_of_file() { _asm ret };
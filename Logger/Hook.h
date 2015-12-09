#ifndef _HOOK_H_
#define _HOOK_H_

#include <map>

#define END_HOOK _asm nop _asm nop _asm nop _asm nop _asm nop

#define pushadx	_asm push eax\
				_asm push ebx\
				_asm push ecx\
				_asm push edx\
				_asm push edi\
				_asm push esi\

#define popadx	_asm pop eax\
				_asm pop ebx\
				_asm pop ecx\
				_asm pop edx\
				_asm pop edi\
				_asm pop esi\

namespace EZ
{
	typedef struct SHookData
	{
		template<typename T>
		SHookData(T pbtramp, unsigned long dwpatchSize, unsigned long dwtrampSize)
		{
			pbTramp = reinterpret_cast<unsigned char*>(pbtramp);
			dwPatchSize = dwpatchSize;
			dwTrampSize = dwtrampSize;
		}
		unsigned char *pbTramp;
		unsigned long dwPatchSize;
		unsigned long dwTrampSize;
	} THookData;

	class CHook
	{
		typedef std::map<void*, THookData> THookMap;

	private:
		THookMap m_mkHooks;

	public:
		CHook();
		virtual ~CHook();

		unsigned char* PlaceHook(unsigned char *pbAddr, unsigned char *pbDst);
		void* PlaceHook(void *lpAddr, void *lpDst);

		bool InsertHook(unsigned char *pbDst, unsigned char *pbTramp, unsigned int iTrampSize, unsigned int iPatchSize);

		template<typename T>
		bool RemoveHook(T pDst)
		{
			return RemoveHook(reinterpret_cast<unsigned char*>(pDst));
		}

		bool RemoveHook(unsigned char *pbDst);

		template<typename T>
		THookData *GetTrampoline(T pAddr)
		{
			unsigned char *pbAddr = reinterpret_cast<unsigned char*>(pAddr);
			if (pbAddr)
			{
				THookMap::iterator it = m_mkHooks.find(pbAddr);
				if (it != m_mkHooks.end())
				{
					return &it->second;
				}
			}

			return nullptr;
		}
	};
};

#endif
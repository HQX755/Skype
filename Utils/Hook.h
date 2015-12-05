#ifndef _HOOK_H_
#define _HOOK_H_

#include <map>

#define END_HOOK _asm nop _asm nop _asm nop _asm nop _asm nop

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

	class EZLIB CHook
	{
		typedef std::map<void*, THookData> THookMap;

	private:
		THookMap m_mkHooks;

	public:
		CHook();
		virtual ~CHook();

#if _MSC_VER >= 1800
		template<typename R, typename... Args>
		typename R(*PlaceHook(R(*args_0)(Args...), R(*args_1)(Args...)))(Args...)
		{
			return reinterpret_cast<R(*)(Args...)>(PlaceHook(reinterpret_cast<void*>(args_0), reinterpret_cast<void*>(args_1)));
		}

		template<typename R, typename... Args>
		typename R(__stdcall*PlaceHook(R(__stdcall*args_0)(Args...), R(__stdcall*args_1)(Args...)))(Args...)
		{
			return reinterpret_cast<R(*)(Args...)>(PlaceHook(reinterpret_cast<void*>(args_0), reinterpret_cast<void*>(args_1)));
		}
#endif

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
#ifndef _ASM_H_
#define _ASM_H_

#include "../include/distorm.h"

namespace EZ
{
	namespace ASM
	{
#define ASM_JMP 0xE9
#define ASM_CALL 0xE8
#define ASM_NOP 0x90

		typedef _DecodedInst TDecodedInstruction;
		typedef struct SInstructionData
		{
			void *data;
			int instructionLenght;
			int instructionCount;
			char instruction[32];
		} TInstructionData;

		TInstructionData GetInstructionLengthAt(unsigned char *pbAddr, const unsigned int iCount = 1);
		TInstructionData GetPossibleFunctionEnd(unsigned char* pbAddr);
		TInstructionData* GetAllFunctionData(unsigned char* pbAddr, unsigned int *p_iCount, const unsigned int iMaxInstructions);
		TInstructionData* GetInstructionJumpTo(unsigned char* pbAddr, unsigned int iRange, TInstructionData pData[], const unsigned int iInstructions);

		template<typename T>
		T TransferCallOffset(T pSrc, T pDst)
		{
			return reinterpret_cast<T>(TransferCallOffset(reinterpret_cast<void*>(pSrc), reinterpret_cast<void*>(pDst)));
		}

		void *TransferCallOffset(void *pSrc, void *pDst);
	};
};

#endif
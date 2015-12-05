#include "stdafx.h"

#include "Asm.h"

#include <cstring>

namespace EZ
{
	namespace ASM
	{
		TInstructionData GetInstructionLengthAt(unsigned char *pbAddr, const unsigned int iCount)
		{
			unsigned int iUsedCount;

			TDecodedInstruction instruction;
			TInstructionData instructionData;

			memset(&instruction, 0, sizeof(TDecodedInstruction));
			memset(&instructionData, 0, sizeof(TInstructionData));

			if (!pbAddr)
			{
				return instructionData;
			}

			instructionData.data = pbAddr;

			if (pbAddr[0] == ASM_JMP)
			{
				pbAddr = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned long*>(pbAddr + 1) +
					reinterpret_cast<unsigned long>(pbAddr + 1) + 4);
			}

			for (unsigned int i = 0; i < iCount; ++i)
			{
				distorm_decode(reinterpret_cast<_OffsetType>(pbAddr), pbAddr, 32, Decode32Bits, &instruction, 1, &iUsedCount);
			}

			unsigned int iLenght = *reinterpret_cast<int*>(instruction.instructionHex.p + 0x18);
			const char *szInstruction = reinterpret_cast<char*>(instruction.mnemonic.p);

			instructionData.instructionCount += iUsedCount;
			instructionData.instructionLenght += iLenght;

			//instructionData.instruction = new char[instruction.mnemonic.length + 1];
			instructionData.instruction[instruction.mnemonic.length] = '\0';

			memcpy(instructionData.instruction, instruction.mnemonic.p, instruction.mnemonic.length);

			return instructionData;
		}

		TInstructionData GetPossibleFunctionEnd(unsigned char* pbAddr)
		{
			unsigned int iUsedCount;
			TDecodedInstruction instruction;

			TInstructionData instructionData;
			TInstructionData instructionDataLast;

			memset(&instruction, 0, sizeof(TDecodedInstruction));
			memset(&instructionData, 0, sizeof(TInstructionData));
			memset(&instructionDataLast, 0, sizeof(TInstructionData));

			if (pbAddr[0] == ASM_JMP)
			{
				pbAddr = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned long*>(pbAddr + 1) +
					reinterpret_cast<unsigned long>(pbAddr + 1) + 4);
			}

			unsigned char *pbCurr = pbAddr;
			while (*reinterpret_cast<unsigned char*>(instruction.instructionHex.p + 0x18) != 0xCC || pbAddr == pbCurr)
			{
				distorm_decode(reinterpret_cast<_OffsetType>(pbCurr), pbCurr, 32, Decode32Bits, &instruction, 1, &iUsedCount);

				instructionData.data = pbCurr;
				instructionData.instructionCount += iUsedCount;
				instructionData.instructionLenght += *reinterpret_cast<unsigned long*>(instruction.instructionHex.p + 0x18);
				//instructionData.instruction = new char[instruction.mnemonic.length + 1];
				instructionData.instruction[instruction.mnemonic.length] = '\0';

				memcpy(instructionData.instruction, instruction.mnemonic.p, instruction.mnemonic.length);

				if (instruction.mnemonic.p[0] == 'I' && instruction.mnemonic.p[1] == 'N' &&
					instruction.mnemonic.p[2] == 'T' && instruction.mnemonic.p[3] == ' ')
				{
					return instructionDataLast;
				}
				else if (instruction.mnemonic.p[0] == 'R' && instruction.mnemonic.p[1] == 'E' &&
					instruction.mnemonic.p[2] == 'T')
				{
					return instructionData;
				}

				instructionDataLast = instructionData;

				pbCurr += *reinterpret_cast<unsigned long*>(instruction.instructionHex.p + 0x18);
			}

			return instructionDataLast;
		}

		TInstructionData* GetAllFunctionData(unsigned char* pbAddr, unsigned int *p_iCount, const unsigned int iMaxInstructions)
		{
			unsigned int iCount = 0;
			unsigned int iUsedCount;

			TDecodedInstruction instruction;
			TInstructionData *instructionData = new TInstructionData[iMaxInstructions];

			memset(&instruction, 0, sizeof(TDecodedInstruction));
			memset(instructionData, 0, sizeof(TInstructionData)* iMaxInstructions);

			if (pbAddr[0] == ASM_JMP)
			{
				pbAddr = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned long*>(pbAddr + 1) +
					reinterpret_cast<unsigned long>(pbAddr + 1) + 4);
			}

			unsigned char *pbCurr = pbAddr;
			while (*reinterpret_cast<unsigned char*>(instruction.instructionHex.p + 0x18) != 0xCC || pbAddr == pbCurr)
			{
				distorm_decode(reinterpret_cast<_OffsetType>(pbCurr), pbCurr, 32, Decode32Bits, &instruction, 1, &iUsedCount);

				instructionData[iCount].data = pbCurr;
				instructionData[iCount].instructionCount += iUsedCount;
				instructionData[iCount].instructionLenght += *reinterpret_cast<unsigned long*>(instruction.instructionHex.p + 0x18);
				//instructionData[iCount].instruction = new char[instruction.mnemonic.length + 1];
				instructionData[iCount].instruction[instruction.mnemonic.length] = '\0';

				memcpy(instructionData[iCount].instruction, instruction.mnemonic.p, instruction.mnemonic.length);

				if (instruction.mnemonic.p[0] == 'I' && instruction.mnemonic.p[1] == 'N' &&
					instruction.mnemonic.p[2] == 'T' && instruction.mnemonic.p[3] == ' ')
				{
					return instructionData;
				}
				else if (instruction.mnemonic.p[0] == 'R' && instruction.mnemonic.p[1] == 'E' &&
					instruction.mnemonic.p[2] == 'T')
				{
					return instructionData;
				}

				pbCurr += *reinterpret_cast<unsigned long*>(instruction.instructionHex.p + 0x18);
				*p_iCount = iCount = iCount + 1;
			}

			return instructionData;
		}

		TInstructionData* GetInstructionJumpTo(unsigned char* pbAddr, unsigned int iRange, TInstructionData pData[], const unsigned int iInstructions)
		{
			TInstructionData *pResult = nullptr;
			for (unsigned int i = 0; i < iInstructions; ++i)
			{
				if (strcmp(pData[i].instruction, "JE") ||
					strcmp(pData[i].instruction, "JNE") ||
					strcmp(pData[i].instruction, "JMP"))
				{
					unsigned long dwAddr = reinterpret_cast<unsigned long>(pData[i].data);
					unsigned long dwDest = reinterpret_cast<unsigned long>(pbAddr);
					if (dwAddr + *reinterpret_cast<unsigned long*>(dwAddr + 1) >= (dwDest) && 
						dwAddr + *reinterpret_cast<unsigned long*>(dwAddr + 1) <= (dwDest + iRange))
					{
						return (pResult = &pData[i]);
					}
				}
			}

			return pResult;
		}

		void *TransferCallOffset(void *pSrc, void *pDst)
		{
			if (!pSrc)
			{
				return nullptr;
			}

			if (!pDst)
			{
				return nullptr;
			}

			if (reinterpret_cast<unsigned char*>(pSrc)[0] != ASM_CALL)
			{
				return nullptr;
			}

			unsigned long dwSrc = reinterpret_cast<unsigned long>(pSrc);
			unsigned long dwDst = reinterpret_cast<unsigned long>(pDst);
			unsigned long dwCall = *reinterpret_cast<unsigned long*>(dwSrc + 1);
			unsigned long dwOffset = dwCall + dwSrc - dwDst;

			return reinterpret_cast<void*>(dwOffset);
		}
	}
}
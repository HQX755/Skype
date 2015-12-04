#include "stdafx.h"

#include "Hook.h"
#include "../include/distorm.h"

#include "Asm.h"

#include <algorithm>
#include <Windows.h>

namespace EZ
{
	CHook::CHook()
	{
	}

	CHook::~CHook()
	{
		std::for_each(m_mkHooks.begin(), m_mkHooks.end(), [&](THookMap::value_type &val)
		{
			RemoveHook(val.first);
		});
	}

	bool CHook::InsertHook(unsigned char *pbDst, unsigned char *pbTramp, unsigned int iTrampSize, unsigned int iPatchSize)
	{
		if (pbDst != nullptr && 
			pbTramp != nullptr && 
			iTrampSize > 0 && 
			iPatchSize > 0)
		{
			return reinterpret_cast<bool&>(m_mkHooks.insert(THookMap::value_type(pbDst, THookData(pbTramp, iPatchSize, iTrampSize))));
		}

		if (pbTramp != nullptr)
		{
			delete[] pbTramp;
			pbTramp = nullptr;
		}

		return false;
	}

	bool CHook::RemoveHook(unsigned char *pbDst)
	{
		THookMap::iterator it = m_mkHooks.find(pbDst);
		if (it == m_mkHooks.end())
		{
			return false;
		}

		if (it->second.pbTramp != nullptr)
		{
			unsigned long dwOldProtect;
			VirtualProtect(it->first, it->second.dwPatchSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

			if (it->second.pbTramp[0] != ASM_CALL)
			{
				memcpy(it->first, it->second.pbTramp, it->second.dwPatchSize);
			}
			else
			{
				memcpy(it->first, it->second.pbTramp + 5, it->second.dwPatchSize);
			}

			delete[] it->second.pbTramp;
			it->second.pbTramp = nullptr;

			VirtualProtect(it->first, it->second.dwPatchSize, dwOldProtect, nullptr);
		}

		m_mkHooks.erase(it);
		return true;
	}

	void* CHook::PlaceHook(void *lpAddr, void *lpDst)
	{
		return PlaceHook(reinterpret_cast<unsigned char*>(lpAddr), reinterpret_cast<unsigned char*>(lpDst));
	}

	unsigned char* CHook::PlaceHook(unsigned char *pbSrc, unsigned char *pbDst)
	{
		unsigned long dwSrc = reinterpret_cast<unsigned long>(pbSrc);
		unsigned long dwDst = reinterpret_cast<unsigned long>(pbDst);

		unsigned int iCurrInst = 0;
		ASM::TInstructionData dstData[5];

		if (pbDst == nullptr || pbSrc == nullptr)
		{
			return nullptr;
		}

		if (pbDst == pbSrc)
		{
			return nullptr;
		}

		if (pbSrc[0] == ASM_JMP)
		{
			pbSrc = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned long*>(pbSrc + 1) + reinterpret_cast<unsigned long>(pbSrc + 1) + 4);
		}

		unsigned char *pbDstReal = pbDst;
		if (pbDstReal[0] == ASM_JMP)
		{
			pbDstReal = reinterpret_cast<unsigned char*>(*reinterpret_cast<unsigned long*>(pbDstReal + 1) + reinterpret_cast<unsigned long>(pbDstReal + 1) + 4);
		}

		unsigned int iFullCount = 0;
		ASM::TInstructionData *instructions = ASM::GetAllFunctionData(pbDst, &iFullCount, 256);
		if (iFullCount == 0)
		{
			delete[] instructions;
			return nullptr;
		}

		ASM::TInstructionData lastInstruction = ASM::GetPossibleFunctionEnd(pbDst);
		if (lastInstruction.data == nullptr)
		{
			delete[] instructions;
			return nullptr;
		}

		int iDstSize = lastInstruction.instructionLenght;
		int iAdditionalLenght = 0;

		unsigned char *szAdditionalData = nullptr;
		if (strcmp(lastInstruction.instruction, "RET") != 0 &&
			strcmp(lastInstruction.instruction, "JMP") != 0)
		{
			unsigned int iLastInstruction = 1;
			do
			{
				iAdditionalLenght += (lastInstruction = instructions[iFullCount - iLastInstruction]).instructionLenght;
				iLastInstruction++;
			} while (iAdditionalLenght < 5);

			szAdditionalData = new unsigned char[iAdditionalLenght];
			if (!szAdditionalData)
			{
				delete[] instructions;
				return nullptr;
			}

			unsigned int iOffset = 0;
			for (unsigned int i = 0; i < iLastInstruction - 1; ++i)
			{
				memcpy(szAdditionalData + iOffset, instructions[iFullCount + i - 1 - (iLastInstruction - 2)].data, 
					instructions[iFullCount + i - 1 - (iLastInstruction - 2)].instructionLenght);

				iOffset += instructions[iFullCount + i - 1 - (iLastInstruction - 2)].instructionLenght;
			}
		}

		iCurrInst = 0;
		dstData[iCurrInst] = ASM::GetInstructionLengthAt(pbSrc);
		iCurrInst++;

		int iPatchSize = dstData[iCurrInst - 1].instructionLenght;
		if (iPatchSize <= 0)
		{
			delete[] instructions;
			delete[] szAdditionalData;

			return nullptr;
		}

		while (iPatchSize < 5)
		{
			dstData[iCurrInst] = ASM::GetInstructionLengthAt(pbSrc + iPatchSize);	iCurrInst++;

			int iAddSize = dstData[iCurrInst - 1].instructionLenght;
			if (iAddSize <= 0)
			{
				delete[] instructions;
				delete[] szAdditionalData;

				return nullptr;
			}
			else
			{
				iPatchSize += iAddSize;
			}
		}

		unsigned char *pbTramp = new unsigned char[iPatchSize + iAdditionalLenght + 11];
		unsigned long dwTramp = reinterpret_cast<unsigned long>(pbTramp);
		if (!pbTramp)
		{
			delete[] szAdditionalData;
			delete[] instructions;

			return nullptr;
		}

		unsigned long dwProtectDst, dwProtectSrc, dwProtectTramp;
		if (!VirtualProtect(pbSrc, 5, PAGE_EXECUTE_READWRITE, &dwProtectSrc) ||
			!VirtualProtect(pbDst, 5, PAGE_EXECUTE_READWRITE, &dwProtectDst) ||
			!VirtualProtect(pbTramp, iPatchSize + iAdditionalLenght + 11, PAGE_EXECUTE_READWRITE, &dwProtectTramp))
		{
			delete[] szAdditionalData;
			delete[] instructions;

			return nullptr;
		}

		if (szAdditionalData != nullptr)
		{
			memcpy(pbTramp, pbSrc, iPatchSize);
		}
		else
		{
			memcpy(pbTramp + 5, pbSrc, iPatchSize);
		}

		int iLength = 0;
		for (unsigned int i = 0; i < iCurrInst; ++i)
		{
			if (strcmp(dstData[i].instruction, "CALL") == 0)
			{
				*reinterpret_cast<unsigned long*>(dwTramp + iLength + 1) = 
					ASM::TransferCallOffset(dwSrc + iLength, dwTramp + iLength);
			}

			iLength += dstData[i].instructionLenght;
		}

		if (szAdditionalData)
		{
			memcpy(pbTramp + iPatchSize + 5, szAdditionalData, iAdditionalLenght);
			VirtualProtect(pbDstReal, iDstSize, PAGE_EXECUTE_READWRITE, &dwProtectDst);

			if (iAdditionalLenght >= 5)
			{
				for (int i = 0; i < iAdditionalLenght - 4; ++i)
				{
					if (szAdditionalData[i] == ASM_CALL || szAdditionalData[i] == ASM_JMP)
					{
						*reinterpret_cast<unsigned long*>(pbTramp + iPatchSize + 4 + (iAdditionalLenght - 4)) = 
							ASM::TransferCallOffset(reinterpret_cast<unsigned long>(pbDstReal)+iDstSize - iAdditionalLenght + i, dwTramp + iPatchSize + (iAdditionalLenght)-1);
					}
				}
			}

			*reinterpret_cast<unsigned char*>(lastInstruction.data) = 0xE9;

			*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned long>(lastInstruction.data) + 1) = 
				reinterpret_cast<unsigned long>(pbTramp + iPatchSize) - reinterpret_cast<unsigned long>(lastInstruction.data);

			delete[] szAdditionalData;
		}

		for (unsigned int i = 0; i < iCurrInst; ++i)
		{
			if (strcmp(dstData[i].instruction, "JMP") == 0 || strcmp(dstData[i].instruction, "CALL") == 0)
			{
				unsigned long dwData = reinterpret_cast<unsigned long>(dstData[i].data) + 1;

				*reinterpret_cast<unsigned long*>(dwData) = 
					reinterpret_cast<unsigned long>(pbSrc)-*reinterpret_cast<unsigned long*>(dwData)+static_cast<unsigned long>(dwData + 5 + 5);
			}
		}

		pbSrc[0] = ASM_JMP;

		if (szAdditionalData != nullptr)
		{
			pbTramp[iPatchSize] = ASM_JMP;
			*reinterpret_cast<unsigned long*>(pbTramp + iPatchSize + 1) = 
				reinterpret_cast<unsigned long>(pbDst) - reinterpret_cast<unsigned long>(pbTramp) - iPatchSize - 5;
		}
		else
		{
			pbTramp[0] = ASM_JMP;
			*reinterpret_cast<unsigned long*>(pbTramp + 1) = 
				reinterpret_cast<unsigned long>(pbDst) - reinterpret_cast<unsigned long>(pbTramp) - 5;
		}

		pbTramp[iPatchSize + iAdditionalLenght + 5] = ASM_JMP;

		*reinterpret_cast<unsigned long*>(pbSrc + 1) = 
			reinterpret_cast<unsigned long>(pbTramp)-reinterpret_cast<unsigned long>(pbSrc)-5;

		*reinterpret_cast<unsigned long*>(pbTramp + iPatchSize + iAdditionalLenght + 5 + 1) = 
			reinterpret_cast<unsigned long>(pbSrc)-reinterpret_cast<unsigned long>(pbTramp)-iPatchSize - 5 - iAdditionalLenght + (iPatchSize - 5);

		for (int i = 5; i < iPatchSize; ++i)
		{
			pbSrc[i] = ASM_NOP;
		}

		VirtualProtect(pbSrc, 5, dwProtectSrc, &dwProtectSrc);
		VirtualProtect(pbDst, iDstSize, dwProtectDst, &dwProtectDst);

		if (instructions != nullptr)
		{
			delete[] instructions;
			instructions = nullptr;
		}

		if (InsertHook(pbDst, pbTramp, iPatchSize + iAdditionalLenght + 11, iPatchSize))
		{
			return (szAdditionalData != nullptr ? reinterpret_cast<unsigned char*>(dwTramp + iPatchSize + iAdditionalLenght + 5) :
				reinterpret_cast<unsigned char*>(dwTramp + 5));
		}

		return nullptr;
	}
};
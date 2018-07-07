#pragma once

#include <cstdint>
#include <windows.h>
#include <cstring>
#include <psapi.h>

namespace IgroWidgets
{
	class FindPattern
	{
	public:
		static uintptr_t ScanExternal(const HANDLE processHanlde, const HMODULE moduleHandle, const unsigned char* pattern, const char* mask)
		{
			uintptr_t result = 0;
			MODULEINFO info = { };
			const auto moduleAddress = reinterpret_cast<uintptr_t>(moduleHandle);
			if(GetModuleInformation(processHanlde, moduleHandle, &info, sizeof(MODULEINFO)))
			{
				byte* buffer = new byte[info.SizeOfImage];
				if(ReadProcessMemory(processHanlde, moduleHandle, buffer, info.SizeOfImage, nullptr) != 0)
				{
					const auto offset = ScanDump(buffer, info.SizeOfImage, pattern, mask);
					if(offset > -1)
					{
						result = moduleAddress + offset;
					}
					delete[] buffer;
				}				
			}
			return result;
		}

		static uintptr_t Scan(const HANDLE processHanlde, const HMODULE moduleHandle, const unsigned char* pattern, const char* mask)
		{
			uintptr_t result = 0;
			MODULEINFO info = { };			
			if(GetModuleInformation(processHanlde, moduleHandle, &info, sizeof(MODULEINFO)))
			{
				result = Scan(reinterpret_cast<uintptr_t>(moduleHandle), info.SizeOfImage, pattern, mask);
			}
			return result;
		}

		static uintptr_t Scan(const uintptr_t start, const size_t length, const unsigned char* pattern, const char* mask)
		{
			size_t pos = 0;
			const auto maskLength = std::strlen(mask) - 1;

			uintptr_t tmpAddress = 0;
			const auto moduleLength = start + length - 1;
			for (auto it = start; it < moduleLength; ++it)
			{
				if (*reinterpret_cast<unsigned char*>(it) == pattern[pos] || mask[pos] == '?')
				{					
					if (mask[pos + 1] == '\0')
					{
						return it - maskLength;
					}
					if(tmpAddress == 0)
					{
						tmpAddress = it;
					}
					pos++;
				}
				else
				{
					if(tmpAddress > 0)
					{
						it = tmpAddress;
						tmpAddress = 0;
					}
					pos = 0;
				}
			}

			return 0;
		}

		static int64_t ScanDump(const byte * dump, const size_t length, const unsigned char* pattern, const char* mask)
		{
			size_t patternPos = 0;
			const auto maskLength = std::strlen(mask) - 1;

			int64_t tmpOffset = -1;
			for (int64_t offset = 0; offset < length - 1; ++offset)
			{
				if (*reinterpret_cast<unsigned char*>(dump[offset]) == pattern[patternPos] || mask[patternPos] == '?')
				{					
					if (mask[patternPos + 1] == '\0')
					{
						return offset - maskLength;
					}
					if(tmpOffset == -1)
					{
						offset = tmpOffset;
					}
					patternPos++;
				}
				else
				{
					if(tmpOffset > -1)
					{
						offset = tmpOffset;
						tmpOffset = -1;
					}
					patternPos = 0;
				}
			}

			return -1;
		}		
	};	
}



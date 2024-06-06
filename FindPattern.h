#pragma once

#include <cstdint>
#include <windows.h>
#include <cstring>
#include <psapi.h>

/**
 * Author: Igromanru
 * Credits: KN4CK3R, SilverDeath, Dr.Pepper
 * Date: 7.07.2018
 */
namespace IgroWidgets
{
    inline size_t FindPatternDump(const unsigned char* dump, const size_t length, const unsigned char* pattern, const char* mask, size_t& outOffset)
    {
        const size_t maskLength = std::strlen(mask) - 1;
        size_t patternPos = 0;
        size_t tmpOffset = -1;
        for (size_t offset = 0; offset < length - 1; ++offset)
        {
            if (dump[offset] == pattern[patternPos] || mask[patternPos] == '?')
            {
                if (mask[patternPos + 1] == '\0')
                {
                    outOffset = (offset - maskLength);
                    return true;
                }
                if (tmpOffset == static_cast<size_t>(-1))
                {
                    tmpOffset = offset;
                }
                patternPos++;
            }
            else
            {
                if (tmpOffset > static_cast<size_t>(-1))
                {
                    offset = tmpOffset;
                    tmpOffset = static_cast<size_t>(-1);
                }
                patternPos = 0;
            }
        }

        return false;
    }

    inline uintptr_t FindPatternExternal(HANDLE processHanlde, HMODULE moduleHandle, const unsigned char* pattern, const char* mask)
    {
        uintptr_t result = 0;
        MODULEINFO info;
        SecureZeroMemory(&info, sizeof(info));
        const auto moduleAddress = reinterpret_cast<uintptr_t>(moduleHandle);
        if (GetModuleInformation(processHanlde, moduleHandle, &info, sizeof(MODULEINFO)))
        {
            auto buffer = new unsigned char[info.SizeOfImage];
            if (ReadProcessMemory(processHanlde, moduleHandle, buffer, info.SizeOfImage, nullptr) != 0)
            {
                size_t offset;
                if (FindPatternDump(buffer, info.SizeOfImage, pattern, mask, offset))
                {
                    result = moduleAddress + offset;
                }
            }
            delete[] buffer;
        }
        return result;
    }

    inline bool MatchPattern(const uintptr_t start, const unsigned char* pattern, const char* mask)
    {
        for (size_t i = 0; mask[i]; i++)
        {
            if (mask[i] != '?' && reinterpret_cast<const unsigned char*>(start)[i] != pattern[i])
            {
                return false;
            }
        }

        return true;
    }

    inline uintptr_t FindPattern(const uintptr_t start, const size_t length, const unsigned char* pattern, const char* mask)
    {
        const auto last = start + length - std::strlen(mask);

        for (auto it = start; it <= last; ++it)
        {
            if (MatchPattern(it, pattern, mask)) return it;
        }

        return 0;
    }

    inline uintptr_t FindPattern(const HANDLE processHanlde, const HMODULE moduleHandle, const unsigned char* pattern, const char* mask)
    {
        uintptr_t result = 0;
        MODULEINFO info;
        SecureZeroMemory(&info, sizeof(info));
        if (GetModuleInformation(processHanlde, moduleHandle, &info, sizeof(MODULEINFO)))
        {
            result = FindPattern(reinterpret_cast<uintptr_t>(moduleHandle), info.SizeOfImage, pattern, mask);
        }
        return result;
    }

    inline uintptr_t FindPattern(const HMODULE moduleHandle, const unsigned char* pattern, const char* mask)
    {
        return FindPattern(GetCurrentProcess(), moduleHandle, pattern, mask);
    }

    inline uintptr_t ReadRIPAddress(HANDLE processHanlde, const uintptr_t address, const uint32_t firstOffset, const uint32_t secondOffset)
    {
        uintptr_t result = 0;
        uint32_t offset;
        if (ReadProcessMemory(processHanlde, reinterpret_cast<LPCVOID>(address + firstOffset), &offset, sizeof(uint32_t), nullptr) != 0)
        {
            result = address + offset + secondOffset;
        }
        return result;
    }

    inline uintptr_t ReadRIPAddressPtr(HANDLE processHanlde, const uintptr_t address, const uint32_t firstOffset, const uint32_t secondOffset)
    {
        uintptr_t result = 0;
        uint32_t offset;
        if (ReadProcessMemory(processHanlde, reinterpret_cast<LPCVOID>(address + firstOffset), &offset, sizeof(uint32_t), nullptr) != 0)
        {
            uintptr_t tmpResult;
            if (ReadProcessMemory(processHanlde, reinterpret_cast<LPCVOID>(address + offset + secondOffset), &tmpResult, sizeof(uintptr_t), nullptr) != 0)
            {
                result = tmpResult;
            }
        }
        return result;
    }
}



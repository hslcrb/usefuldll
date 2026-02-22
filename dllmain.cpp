// UsefulDLL - 유틸리티 DLL
// Library name: UsefulDLL
// 설명: 범용으로 사용 가능한 가벼운 유틸리티 기능을 제공하는 DLL
// Description: A lightweight utility DLL providing small, broadly useful functions
// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다. (한/영)
#include "pch.h"
#include <windows.h>
#include <stdio.h>

// 최소한의 C 스타일 유틸리티 구현: stdio.h 기반으로 동작하도록 의존성 최소화
// Minimal C-style helpers to avoid relying on additional headers
static unsigned int my_strlen(const char* s)
{
    const char* p = s;
    while (*p) ++p;
    return (unsigned int)(p - s);
}

static void* my_memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dest;
}


// DllMain: DLL 진입점 — 프로세스/스레드 연결과 해제를 처리합니다.
// DllMain: DLL entry point — handles process/thread attach and detach notifications.
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ----------------------------
// UsefulDLL exported helpers / 유용한 DLL 내보내기 함수들
// ----------------------------

extern "C" {

// GetUsefulDllVersion
// 반환: 정수형 버전 (major * 100 + minor)
// Return: integer version number (major * 100 + minor)
__declspec(dllexport) int WINAPI GetUsefulDllVersion()
{
    return 100; // v1.00
}

// GetUsefulDllGreeting
// 설명: 호출자 버퍼에 간단한 인사문구를 씁니다. (버퍼이상시 필요크기를 반환)
// Description: Writes a short greeting into the caller-provided buffer. Returns required length (including null) or the needed size if buffer is NULL or too small.
__declspec(dllexport) int WINAPI GetUsefulDllGreeting(char* buffer, size_t bufferSize)
{
    const char* msg = "UsefulDLL v1.00 - lightweight utility DLL";
    unsigned int needed = my_strlen(msg) + 1;
    if (!buffer) return (int)needed;
    if (bufferSize < needed) return (int)needed;
    my_memcpy(buffer, msg, needed);
    return (int)needed;
}

// ReverseStringA
// 설명: ASCII/UTF-8 바이트 단위로 문자열을 역순으로 복사합니다. (멀티바이트 문자 경계는 보장하지 않음)
// Description: Reverses a string byte-wise (ASCII/UTF-8). Note: does not preserve multi-byte character boundaries.
// 반환: 필요 버퍼 크기(널 포함) 또는 오류시 -1
// Return: required buffer size (including null) or -1 on error
__declspec(dllexport) int WINAPI ReverseStringA(const char* input, char* output, size_t outputSize)
{
    if (!input)
        return -1;
    unsigned int len = my_strlen(input);
    unsigned int needed = len + 1;
    if (!output)
        return (int)needed;
    if (outputSize < needed)
        return (int)needed;
    // If caller provided the same buffer for input and output, reverse in-place to avoid extra memory movement.
    if (output == input) {
        char* s = reinterpret_cast<char*>(output);
        size_t i = 0, j = (len == 0 ? 0 : len - 1);
        while (i < j) {
            char tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
            ++i; --j;
        }
        return (int)needed;
    }
    // Copy reversed using pointers for minimal overhead
    const char* p = input + len;
    char* o = output;
    while (p != input) {
        --p;
        *o++ = *p;
    }
    *o = '\0';
    return (int)needed;
}

// CRC32 테이블 및 slicing-by-8 초기화 (성능 향상)
// CRC32 tables and slicing-by-8 initializer
static unsigned int crc32_table[8][256];
static volatile long crc_state = 0; // 0 = uninit, 1 = initializing, 2 = ready
static void init_crc32_table()
{
    // Attempt to become initializer
    if (InterlockedCompareExchange(&crc_state, 1, 0) == 0) {
        const unsigned int poly = 0xEDB88320u;
        // table[0]
        for (unsigned int i = 0; i < 256; ++i) {
            unsigned int crc = i;
            for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ ((crc & 1) ? poly : 0);
            crc32_table[0][i] = crc;
        }
        // Build slicing-by-8 tables
        for (int t = 1; t < 8; ++t) {
            for (unsigned int i = 0; i < 256; ++i) {
                unsigned int v = crc32_table[t-1][i];
                crc32_table[t][i] = (v >> 8) ^ crc32_table[0][v & 0xFFu];
            }
        }
        // Mark ready
        InterlockedExchange(&crc_state, 2);
    } else {
        // Wait until ready
        while (crc_state != 2) {
            Sleep(0);
        }
    }
}

// ComputeCRC32
// 설명: 주어진 버퍼에 대해 CRC32(IEEE 802.3)를 계산하여 반환합니다.
// Description: Computes CRC32 (IEEE 802.3) for the provided buffer and returns the checksum.
__declspec(dllexport) unsigned int WINAPI ComputeCRC32(const void* data, size_t len)
{
    if (!data) return 0;
    init_crc32_table();
    unsigned int crc = 0xFFFFFFFFu;
    const unsigned char* p = (const unsigned char*)data;

    // Use slicing-by-8 for higher throughput on large buffers
    while (len >= 8) {
        unsigned int a = (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
        unsigned int b = (unsigned int)p[4] | ((unsigned int)p[5] << 8) | ((unsigned int)p[6] << 16) | ((unsigned int)p[7] << 24);
        crc ^= a;
        crc = crc32_table[7][ crc        & 0xFFu ] ^
              crc32_table[6][ (crc >> 8)  & 0xFFu ] ^
              crc32_table[5][ (crc >> 16) & 0xFFu ] ^
              crc32_table[4][ (crc >> 24) & 0xFFu ] ^
              crc32_table[3][  b         & 0xFFu ] ^
              crc32_table[2][ (b >> 8)   & 0xFFu ] ^
              crc32_table[1][ (b >> 16)  & 0xFFu ] ^
              crc32_table[0][ (b >> 24)  & 0xFFu ];
        p += 8;
        len -= 8;
    }
    // Process remaining bytes
    while (len--) {
        crc = (crc >> 8) ^ crc32_table[0][ (crc ^ *p++) & 0xFFu ];
    }
    return crc ^ 0xFFFFFFFFu;
}

// Base64 인코딩/디코딩을 위한 간단한 구현
// Simple Base64 encode/decode helpers
static const char* b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64Encode
// 설명: 입력 바이트열을 Base64로 인코딩합니다. 출력 버퍼이상시 필요크기를 반환합니다.
// Description: Encodes input bytes to Base64. Returns required output size (including null) or needed size if out is NULL or too small.
__declspec(dllexport) int WINAPI Base64Encode(const unsigned char* data, size_t dataLen, char* out, size_t outSize)
{
    if (!data) return -1;
    size_t needed = ((dataLen + 2) / 3) * 4 + 1;
    if (!out) return (int)needed;
    if (outSize < needed) return (int)needed;
    const unsigned char* p = data;
    const unsigned char* pend = data + dataLen;
    char* o = out;
    // Process full 3-byte blocks
    size_t full = dataLen / 3;
    for (size_t i = 0; i < full; ++i) {
        uint32_t val = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
        *o++ = b64_chars[(val >> 18) & 0x3F];
        *o++ = b64_chars[(val >> 12) & 0x3F];
        *o++ = b64_chars[(val >> 6) & 0x3F];
        *o++ = b64_chars[val & 0x3F];
        p += 3;
    }
    // Tail
    size_t rem = pend - p;
    if (rem) {
        uint32_t val = (uint32_t)p[0] << 16;
        if (rem == 2) val |= (uint32_t)p[1] << 8;
        *o++ = b64_chars[(val >> 18) & 0x3F];
        *o++ = b64_chars[(val >> 12) & 0x3F];
        *o++ = (rem == 2) ? b64_chars[(val >> 6) & 0x3F] : '=';
        *o++ = '=';
    }
    *o = '\0';
    return (int)needed;
}

// b64_index: Base64 문자에서 값으로 매핑
// b64_index: maps a Base64 character to its 6-bit value
static inline int b64_index(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Base64Decode
// 설명: Base64 문자열을 디코딩하여 바이트로 복원합니다. 출력 버퍼가 NULL이면 필요 크기를 반환합니다.
// Description: Decodes a Base64 string into bytes. If out is NULL, returns the required output size.
__declspec(dllexport) int WINAPI Base64Decode(const char* in, unsigned char* out, size_t outSize)
{
    if (!in) return -1;
    unsigned int inLen = my_strlen(in);
    if (inLen % 4 != 0) return -1;
    unsigned int expected = (inLen / 4) * 3;
    if (inLen >= 1 && in[inLen-1] == '=') --expected;
    if (inLen >= 2 && in[inLen-2] == '=') --expected;
    if (!out) return (int)expected;
    if (outSize < expected) return (int)expected;
    const char* p = in;
    const char* pend = in + inLen;
    unsigned char* o = out;
    while (p < pend) {
        int v0 = b64_index(p[0]);
        int v1 = b64_index(p[1]);
        int v2 = (p[2] == '=') ? -2 : b64_index(p[2]);
        int v3 = (p[3] == '=') ? -2 : b64_index(p[3]);
        if (v0 < 0 || v1 < 0 || (v2 < -1) || (v3 < -1)) return -1;
        unsigned int val = ( (unsigned int)v0 << 18 ) | ( (unsigned int)v1 << 12 );
        if (v2 >= 0) val |= ((unsigned int)v2 << 6);
        if (v3 >= 0) val |= (unsigned int)v3;
        *o++ = (unsigned char)((val >> 16) & 0xFFu);
        if (v2 >= 0) *o++ = (unsigned char)((val >> 8) & 0xFFu);
        if (v3 >= 0) *o++ = (unsigned char)(val & 0xFFu);
        p += 4;
    }
    return (int)expected;
}

// GetUsefulDllSystemInfo
// 설명: 간단한 시스템 정보를 문자열로 작성합니다. 예: "Arch=x64; Cores=8"
// Description: Writes a small system info string into the caller buffer. Example: "Arch=x64; Cores=8"
// 반환: 필요 길이(널 포함) 또는 오류시 -1
// Return: required length (including null) or -1 on error
__declspec(dllexport) int WINAPI GetUsefulDllSystemInfo(char* buffer, size_t bufferSize)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const char* arch = "Unknown";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: arch = "x64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
    case PROCESSOR_ARCHITECTURE_ARM: arch = "ARM"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: arch = "ARM64"; break;
    default: arch = "Unknown"; break;
    }
    char temp[64];
    int n = sprintf_s(temp, sizeof(temp), "%s; Cores=%u", arch, (unsigned)si.dwNumberOfProcessors);
    if (n < 0) return -1;
    unsigned int needed = (unsigned int)n + 1u;
    if (!buffer) return (int)needed;
    if (bufferSize < needed) return (int)needed;
    my_memcpy(buffer, temp, needed);
    return (int)needed;
}

} // extern "C"



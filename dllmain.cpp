#// UsefulDLL - 유틸리티 DLL
// Library name: UsefulDLL
// 설명: 범용으로 사용 가능한 가벼운 유틸리티 기능을 제공하는 DLL
// Description: A lightweight utility DLL providing small, broadly useful functions
// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다. (한/영)
#include "pch.h"
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

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
    size_t needed = strlen(msg) + 1;
    if (!buffer)
        return (int)needed;
    if (bufferSize < needed)
        return (int)needed;
    memcpy(buffer, msg, needed);
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
    size_t len = strlen(input);
    size_t needed = len + 1;
    if (!output)
        return (int)needed;
    if (outputSize < needed)
        return (int)needed;
    for (size_t i = 0; i < len; ++i)
        output[i] = input[len - 1 - i];
    output[len] = '\0';
    return (int)needed;
}

// CRC32 테이블과 초기화
// CRC32 table and initializer (IEEE 802.3 polynomial)
static uint32_t crc32_table[256];
static void init_crc32_table()
{
    static bool inited = false;
    if (inited) return;
    const uint32_t poly = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ ((crc & 1) ? poly : 0);
        crc32_table[i] = crc;
    }
    inited = true;
}

// ComputeCRC32
// 설명: 주어진 버퍼에 대해 CRC32(IEEE 802.3)를 계산하여 반환합니다.
// Description: Computes CRC32 (IEEE 802.3) for the provided buffer and returns the checksum.
__declspec(dllexport) uint32_t WINAPI ComputeCRC32(const void* data, size_t len)
{
    if (!data) return 0;
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFFu;
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; ++i)
        crc = (crc >> 8) ^ crc32_table[(crc ^ p[i]) & 0xFFu];
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
    size_t oi = 0;
    for (size_t i = 0; i < dataLen; i += 3) {
        uint32_t val = data[i] << 16;
        if (i + 1 < dataLen) val |= data[i+1] << 8;
        if (i + 2 < dataLen) val |= data[i+2];
        int idx0 = (val >> 18) & 0x3F;
        int idx1 = (val >> 12) & 0x3F;
        int idx2 = (val >> 6) & 0x3F;
        int idx3 = val & 0x3F;
        out[oi++] = b64_chars[idx0];
        out[oi++] = b64_chars[idx1];
        out[oi++] = (i + 1 < dataLen) ? b64_chars[idx2] : '=';
        out[oi++] = (i + 2 < dataLen) ? b64_chars[idx3] : '=';
    }
    out[oi] = '\0';
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
    size_t inLen = strlen(in);
    if (inLen % 4 != 0) return -1;
    size_t expected = (inLen / 4) * 3;
    if (inLen >= 1 && in[inLen-1] == '=') --expected;
    if (inLen >= 2 && in[inLen-2] == '=') --expected;
    if (!out) return (int)expected;
    if (outSize < expected) return (int)expected;
    size_t oi = 0;
    for (size_t i = 0; i < inLen; i += 4) {
        int v0 = b64_index(in[i]);
        int v1 = b64_index(in[i+1]);
        int v2 = (in[i+2] == '=') ? -2 : b64_index(in[i+2]);
        int v3 = (in[i+3] == '=') ? -2 : b64_index(in[i+3]);
        if (v0 < 0 || v1 < 0 || (v2 < -1) || (v3 < -1)) return -1;
        uint32_t val = (v0 << 18) | (v1 << 12);
        if (v2 >= 0) val |= (v2 << 6);
        if (v3 >= 0) val |= v3;
        out[oi++] = (val >> 16) & 0xFF;
        if (v2 >= 0) out[oi++] = (val >> 8) & 0xFF;
        if (v3 >= 0) out[oi++] = val & 0xFF;
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
    std::ostringstream ss;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    ss << "Arch=";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: ss << "x64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: ss << "x86"; break;
    case PROCESSOR_ARCHITECTURE_ARM: ss << "ARM"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: ss << "ARM64"; break;
    default: ss << "Unknown"; break;
    }
    ss << "; Cores=" << si.dwNumberOfProcessors;
    std::string s = ss.str();
    size_t needed = s.size() + 1;
    if (!buffer) return (int)needed;
    if (bufferSize < needed) return (int)needed;
    memcpy(buffer, s.c_str(), needed);
    return (int)needed;
}

} // extern "C"



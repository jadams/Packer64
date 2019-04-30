#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <iostream>
#include <vector>
#include <tchar.h>
#include <atlconv.h>
#include "open.h"
#include "quicklz.h"
#include "cRC4.h"

#define KEY_LEN 128
#define BUFFER_RSRC_ID 10
#define FILE_SIZE_RSRC_ID 20
#define KEY_RSRC_ID 30

BYTE* GenerateKey();
bool EncryptPE(std::vector<BYTE>& bin);
bool DecryptPE(std::vector<BYTE>& bin);
bool CompressPE(std::vector<BYTE>& bin);
bool DecompressPE(std::vector<BYTE>& bin);
BOOL ProcessReplacement(TCHAR* target, std::vector<BYTE> bin);

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff567119(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

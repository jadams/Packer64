#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <tchar.h>
#include <atlconv.h>
#include "..\Packer\open.h"
#include "..\Packer\quicklz.h"
#include "..\Packer\cRC4.h"

#define KEY_LEN 128

bool DecryptPE(std::vector<BYTE>& bin);
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

struct PE_FILE
{
	size_t size_ids{};
	size_t size_dos_stub{};
	size_t size_inh32{};
	size_t size_ish{};
	size_t size_sections{};
	IMAGE_DOS_HEADER ids;
	std::vector<char> MS_DOS_STUB;
	IMAGE_NT_HEADERS64 inh32;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<std::shared_ptr<char>> Sections;
	void set_sizes(size_t, size_t, size_t, size_t, size_t);
};
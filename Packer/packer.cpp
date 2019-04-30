#include "packer.h"

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

BYTE* GenerateKey()
{
	HCRYPTPROV hCryptProv;                      // CSP handle
	BYTE* pbData{};
	pbData = new BYTE[KEY_LEN];

	if (CryptAcquireContext(
		&hCryptProv,        // Address for handle to be returned.
		NULL,               // Use the current user's logon name.
		NULL,               // Use the default provider.
		PROV_RSA_FULL,      // Need to both encrypt and sign.
		NULL))
	{
		DbgPrint("[+] Got context");
	}
	else
	{
		DbgPrint("[-] Failed to get context");
	}

	if (CryptGenRandom(		// Generate a random KEY_LEN key
		hCryptProv,
		KEY_LEN,
		pbData))
	{
		DbgPrint("[+] Generated random");
	}
	else
	{
		DbgPrint("[-] Failed to generate random");
	}

	if (CryptReleaseContext(hCryptProv, 0))
	{
		DbgPrint("[+] Released context");
	}
	else
	{
		DbgPrint("[-] Failed to release context");
	}

	//cout << "Using key: ";
	//for (int i = 0; i < KEY_LEN; i++)
	//	cout << hex << (unsigned int)pbData[i];
	//cout << endl;

	return pbData;
}

bool EncryptPE(std::vector<BYTE>& bin)
{
	BYTE* pbKey;
	pbKey = GenerateKey();
	CRC4* rc4;
	rc4 = new CRC4{};
	rc4->Initialize(pbKey, KEY_LEN);
	rc4->RC4(&bin.front(), bin.size());
	delete rc4;
	bin.insert(bin.end(), pbKey, pbKey + KEY_LEN);
	return true;
}

bool DecryptPE(std::vector<BYTE>& bin)
{
	std::vector<BYTE> pvKey(bin.end() - KEY_LEN, bin.end());
	bin.erase(bin.end() - KEY_LEN, bin.end());
	CRC4* rc4;
	rc4 = new CRC4{};
	rc4->Initialize(&pvKey.front(), KEY_LEN);
	rc4->RC4(&bin.front(), bin.size());
	delete rc4;
	return true;
}

bool CompressPE(std::vector<BYTE>& bin)
{
	qlz_state_compress* state_compress{};
	state_compress = new qlz_state_compress;
	size_t csize;
	csize = bin.size() + 400;
	char* cbin{};
	cbin = new char[csize];
	size_t ncsize = qlz_compress(&bin.front(), cbin, bin.size(), state_compress);
	std::copy(cbin, cbin + ncsize, &bin.front());
	bin.resize(ncsize);
	delete state_compress;
	delete[] cbin;
	return true;
}

bool DecompressPE(std::vector<BYTE>& bin)
{
	qlz_state_decompress* state_decompress{};
	state_decompress = new qlz_state_decompress;
	size_t dsize = qlz_size_decompressed((char*)& bin.front());
	char* dbin{};
	dbin = new char[dsize];
	size_t usize = qlz_decompress((char*)&bin.front(), dbin, state_decompress);
	bin.resize(usize);
	std::copy(dbin, dbin + usize, &bin.front());
	delete state_decompress;
	delete[] dbin;
	return true;
}

bool WritePE(std::vector<BYTE> bin, const char* filename)
{
	std::ofstream file(filename, std::ios::binary | std::ios::out);		// Open the file

	if (file.is_open())
	{
		file.unsetf(std::ios::skipws);			// Fix pooping on newlines

		std::streampos size_of_pe = bin.size();

		std::copy(bin.begin(), bin.end(), std::ostreambuf_iterator<char>(file));

		file.close();

		return true;
	}
	else
	{
		return false;
	}
}

int main(int argc, char* argv[])
{
	USES_CONVERSION;

	std::vector<BYTE> bin = OpenPE(argv[1]);
	std::cout << "[Open] Size: " << bin.size() << std::endl;

	CompressPE(bin);
	std::cout << "[Compression] Size: " << bin.size() << std::endl;

	EncryptPE(bin);
	std::cout << "[Encryption] Size: " << bin.size() << std::endl;


	std::vector<BYTE> stub = OpenPE("PackerStub.exe");
	std::cout << "[Stub] Size: " << stub.size() << std::endl;

	stub.insert(stub.end(), bin.begin(), bin.end());
	std::cout << "[Stub+Bin] Size: " << stub.size() << std::endl;

	size_t stSize = bin.size();
	std::vector<BYTE> vbSize;
	vbSize.reserve(sizeof(stSize));
	vbSize.assign(reinterpret_cast<BYTE*>(&stSize), reinterpret_cast<BYTE*>(&stSize) + sizeof(stSize));
	
	stub.insert(stub.end(), vbSize.begin(), vbSize.end());
	std::cout << "[Stub+Bin+Size] Size: " << stub.size() << std::endl;
	WritePE(stub, argv[2]);

	return EXIT_SUCCESS;
}
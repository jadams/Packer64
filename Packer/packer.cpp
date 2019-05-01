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
		//DbgPrint("[+] Got context");
	}
	else
	{
		//DbgPrint("[-] Failed to get context");
		return nullptr;
	}

	if (CryptGenRandom(		// Generate a random KEY_LEN key
		hCryptProv,
		KEY_LEN,
		pbData))
	{
		//DbgPrint("[+] Generated random");
	}
	else
	{
		//DbgPrint("[-] Failed to generate random");
		return nullptr;
	}

	if (CryptReleaseContext(hCryptProv, 0))
	{
		//DbgPrint("[+] Released context");
	}
	else
	{
		//DbgPrint("[-] Failed to release context");
	}

	//cout << "Using key: ";
	//for (int i = 0; i < KEY_LEN; i++)
	//	cout << hex << (unsigned int)pbData[i];
	//cout << endl;

	return pbData;
}

bool EncryptPE(std::vector<BYTE>& bin)
{
	BYTE* pbKey = nullptr;
	pbKey = GenerateKey();
	if (pbKey == nullptr)
	{
		return false;
	}
	CRC4* rc4 = nullptr;
	rc4 = new CRC4{};
	rc4->Initialize(pbKey, KEY_LEN);
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
	bin.insert(bin.end(), pbKey, pbKey + KEY_LEN);
	if (bin.size() < 1)
	{
		return false;
	}
	return true;
}

bool CompressPE(std::vector<BYTE>& bin)
{
	qlz_state_compress* state_compress = nullptr;
	state_compress = new qlz_state_compress{};
	if (state_compress == nullptr)
	{
		delete state_compress;
		return false;
	}
	size_t csize;
	csize = bin.size() + 400;
	if (csize < 1)
	{
		delete state_compress;
		return false;
	}
	char* cbin{};
	cbin = new char[csize];
	size_t ncsize = qlz_compress(&bin.front(), cbin, bin.size(), state_compress);
	if (ncsize < 1)
	{
		delete state_compress;
		delete[] cbin;
		return false;
	}
	std::copy(cbin, cbin + ncsize, &bin.front());
	bin.resize(ncsize);
	if (bin.size() < 1)
	{
		delete state_compress;
		delete[] cbin;
		return false;
	}
	delete state_compress;
	delete[] cbin;
	return true;
}

bool WritePE(std::vector<BYTE> bin, const char* filename)
{
	std::ofstream file(filename, std::ios::binary | std::ios::out);		// Open the file

	if (file.is_open())
	{
		file.unsetf(std::ios::skipws);			// Fix pooping on newlines

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
	if (argc < 3)
	{
		std::cerr << argv[0] << " [exe to be packed] [name of packed output]" << std::endl;
		return EXIT_FAILURE;
	}

	USES_CONVERSION;

	std::vector<BYTE> bin = OpenPE(argv[1]);
	if (bin.size() < 1)
	{
		std::cerr << "[ERROR] Could not open " << argv[1] << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Bin Open] Size: " << bin.size() << std::endl;

	if (!CompressPE(bin))
	{
		std::cerr << "[ERROR] Could not compress bin" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Bin Compression] Size: " << bin.size() << std::endl;

	if (!EncryptPE(bin))
	{
		std::cerr << "[ERROR] Could not encrypt bin" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Bin Encryption] Size: " << bin.size() << std::endl;


	std::vector<BYTE> stub = OpenPE("PackerStub.exe");
	if (stub.size() < 1)
	{
		std::cerr << "[ERROR] Could not open PackerStub.exe" << std::endl
			<< "[ERROR] PackerStub.exe must be in same directory as " << argv[0] << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Stub] Size: " << stub.size() << std::endl;

	BYTE* bNoise = GenerateKey();
	if (bNoise == nullptr)
	{
		std::cerr << "[ERROR] Could not generate noise" << std::endl;
		return EXIT_FAILURE;
	}
	std::vector<BYTE> vbNoise(bNoise, bNoise+KEY_LEN);
	if (vbNoise.size() < 1)
	{
		std::cerr << "[ERROR] Could not generate noise" << std::endl;
		return EXIT_FAILURE;
	}
	stub.insert(stub.end(), vbNoise.begin(), vbNoise.end());
	if (stub.size() < 1)
	{
		std::cerr << "[ERROR] Could not insert noise" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Stub+Noise] Size: " << stub.size() << std::endl;

	stub.insert(stub.end(), bin.begin(), bin.end());
	if (stub.size() < 1)
	{
		std::cerr << "[ERROR] Could not insert bin" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Stub+Noise+Bin] Size: " << stub.size() << std::endl;

	size_t stSize = bin.size();
	if (stSize < 1)
	{
		return EXIT_FAILURE;
	}
	std::vector<BYTE> vbSize;
	vbSize.reserve(sizeof(stSize));
	vbSize.assign(reinterpret_cast<BYTE*>(&stSize), reinterpret_cast<BYTE*>(&stSize) + sizeof(stSize));
	if (vbSize.size() < 1)
	{
		std::cerr << "[ERROR] Could not get bin size" << std::endl;
		return EXIT_FAILURE;
	}
	
	stub.insert(stub.end(), vbSize.begin(), vbSize.end());
	if (stub.size() < 1)
	{
		std::cerr << "[ERROR] Could not insert bin size" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Stub+Noise+Bin+Size] Size: " << stub.size() << std::endl;
	if (!WritePE(stub, argv[2]))
	{
		std::cerr << "[ERROR] Could write " << argv[2] << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
#include "open.h"

std::vector<BYTE> OpenPE(const char* filename)
{
	std::ifstream file(filename, std::ios::binary | std::ios::in | std::ios::ate);		// Open the file

	if (file.is_open())
	{
		file.unsetf(std::ios::skipws);			// Fix pooping on newlines

		std::streampos size_of_pe;

		size_of_pe = file.tellg();				// Get filesize
		file.seekg(0, std::ios::beg);

		if (size_of_pe < 1)
		{
			file.close();
			return {};
		}

		std::vector<BYTE> bin;
		bin.reserve(size_of_pe);					// Reserve space for the file

		bin.insert(bin.begin(),					// Read the data into the vector
			std::istream_iterator<BYTE>(file),
			std::istream_iterator<BYTE>());

		file.close();

		return bin;
	}
	else
	{
		return {};
	}
}

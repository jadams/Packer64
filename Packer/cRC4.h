/***********************************************************
	* Standard RC4 algorithm
	* class in C++
	* Written by Viotto - BreakingSecurity.net
***********************************************************/

#include <string>

class CRC4
{
public:

	CRC4(unsigned char* pKey, unsigned int lenKey);
	CRC4();

	void RC4(unsigned char pData[], unsigned long lenData);
	std::string RC4Str(unsigned char* pInputData, unsigned long InputSize);
	void Initialize(unsigned char* pKey, unsigned int lenKey);

private:
	int m_sBox[256]; //substitution-box
	int a, b;
	unsigned char swap;
};
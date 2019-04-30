#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <iterator>

std::vector<BYTE> OpenPE(const char* filename);
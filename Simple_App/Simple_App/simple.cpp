#include <Windows.h>
#include <iostream>

int main(void) {
	std::cout << "Press Enter.." << std::endl;
	getchar();
	MessageBoxA(NULL, "Hello", "Hello World", MB_OK);
	return 0;
}
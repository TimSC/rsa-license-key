#pragma once
#include <string>
#include <iostream>

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

inline std::string ReadPassword()
{
#if defined(__unix__) || defined(__APPLE__)
	struct termios old_t, new_t;
	bool term_ok = (tcgetattr(STDIN_FILENO, &old_t) == 0);
	if (term_ok)
	{
		new_t = old_t;
		new_t.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t);
	}
#elif defined(_WIN32)
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD old_mode = 0;
	bool term_ok = (GetConsoleMode(hStdin, &old_mode) != 0);
	if (term_ok)
		SetConsoleMode(hStdin, old_mode & ~ENABLE_ECHO_INPUT);
#endif

	std::string pass;
	std::cin >> pass;

#if defined(__unix__) || defined(__APPLE__)
	if (term_ok)
	{
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
		std::cout << std::endl;
	}
#elif defined(_WIN32)
	if (term_ok)
	{
		SetConsoleMode(hStdin, old_mode);
		std::cout << std::endl;
	}
#endif

	return pass;
}

#pragma once

#include <Windows.h>
#include <WinINet.h>
#include <IOStream>
#include <String>

#pragma comment(lib, "WinINet.lib")

std::string replaceAll(std::string subject, const std::string& search,
    const std::string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
        subject.replace(pos, search.length(), replace);
        pos += replace.length();
    };
    return subject;
};

std::string DownloadURL(std::string URL) {
    HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
    HINTERNET urlFile;
    std::string rtn;
    if (interwebs) {
        urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
        if (urlFile) {
            char buffer[2000];
            DWORD bytesRead;
            do {
                InternetReadFile(urlFile, buffer, 2000, &bytesRead);
                rtn.append(buffer, bytesRead);
                memset(buffer, 0, 2000);
            } while (bytesRead);
            InternetCloseHandle(interwebs);
            InternetCloseHandle(urlFile);
            std::string p = replaceAll(rtn, "|n", "\r\n");
            return p;
        };
    };
    InternetCloseHandle(interwebs);
    std::string p = replaceAll(rtn, "|n", "\r\n");
    return p;
};

std::string keychecker() {
    std::string key;
    std::cout << "Enter Key: ";
    std::cin >> key;
    return key;
};

void auth() {
    std::string hostfile = ""; //Hwid check site [Pastebin etc.]
    std::string hot = keychecker();
    std::string result = DownloadURL(hostfile += hot);
    if (result == "1") {
        std::cout << "Whitelisted Key: " + hot, +"\n"; //Success message.
    }
    else {
        std::cout << "Key Not Found\n" << hot.c_str();
        Sleep(10000);
        exit(10);
    };
};

// Windows helper for checking a user-entered key against a remote HTTP endpoint.
#pragma once

#include <Windows.h>
#include <WinINet.h>
#include <IOStream>
#include <String>
#include <cctype>
#include <cstring>
#include <crypto++/base64.h>
#include <crypto++/filters.h>
#include <crypto++/queue.h>
#include <crypto++/xed25519.h>

#pragma comment(lib, "WinINet.lib")

// Server response body must be: "1\n<base64 signature>".
// Signature is Ed25519 over: "license-response:v1\nkey=<key>\nstatus=1".
// Base64-encoded DER Ed25519 public key used to verify server responses.
const char* LICENSE_RESPONSE_PUBKEY_BASE64 = "";

bool IsUnreservedUrlChar(unsigned char c) {
    return std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

std::string UrlEncode(const std::string& value) {
    const char hex[] = "0123456789ABCDEF";
    std::string encoded;
    for (size_t i = 0; i < value.size(); i++) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (IsUnreservedUrlChar(c)) {
            encoded.push_back(static_cast<char>(c));
        }
        else {
            encoded.push_back('%');
            encoded.push_back(hex[c >> 4]);
            encoded.push_back(hex[c & 15]);
        }
    }
    return encoded;
}

std::string TrimWhitespace(const std::string& value) {
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
        first++;
    }

    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) {
        last--;
    }

    return value.substr(first, last - first);
}

std::string PostKey(std::string endpoint, std::string key) {
    URL_COMPONENTSA parts;
    memset(&parts, 0, sizeof(parts));

    char host[256];
    char path[2048];
    char extra[2048];
    memset(host, 0, sizeof(host));
    memset(path, 0, sizeof(path));
    memset(extra, 0, sizeof(extra));

    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host;
    parts.dwHostNameLength = sizeof(host);
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = sizeof(path);
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = sizeof(extra);

    if (!InternetCrackUrlA(endpoint.c_str(), 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS) {
        return "";
    }

    std::string pathAndQuery = path;
    pathAndQuery += extra;
    if (pathAndQuery.empty()) {
        pathAndQuery = "/";
    }

    HINTERNET interwebs = InternetOpenA("rsa-license-key", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!interwebs) {
        return "";
    }

    HINTERNET connection = InternetConnectA(interwebs, host, parts.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!connection) {
        InternetCloseHandle(interwebs);
        return "";
    }

    const char* acceptTypes[] = { "text/plain", NULL };
    DWORD flags = INTERNET_FLAG_SECURE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_NO_AUTO_REDIRECT |
        INTERNET_FLAG_PRAGMA_NOCACHE;
    HINTERNET request = HttpOpenRequestA(connection, "POST", pathAndQuery.c_str(), NULL, NULL, acceptTypes, flags, 0);
    if (!request) {
        InternetCloseHandle(connection);
        InternetCloseHandle(interwebs);
        return "";
    }

    std::string body = "key=" + UrlEncode(key);
    const char* headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    BOOL sent = HttpSendRequestA(request, headers, -1L, (LPVOID)body.data(), (DWORD)body.size());
    if (!sent) {
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(interwebs);
        return "";
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL) || statusCode != 200) {
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(interwebs);
        return "";
    }

    std::string rtn;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(request, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (rtn.size() + bytesRead > 1024) {
            rtn.clear();
            break;
        }
        rtn.append(buffer, bytesRead);
    }

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(interwebs);

    return TrimWhitespace(rtn);
}

bool VerifySignedResponse(const std::string& key, const std::string& response) {
    size_t separator = response.find('\n');
    if (separator == std::string::npos) {
        return false;
    }

    std::string status = TrimWhitespace(response.substr(0, separator));
    std::string signatureBase64 = TrimWhitespace(response.substr(separator + 1));
    if (status != "1" || signatureBase64.empty() || strlen(LICENSE_RESPONSE_PUBKEY_BASE64) == 0) {
        return false;
    }

    try {
        CryptoPP::ByteQueue publicKeyBytes;
        CryptoPP::StringSource publicKeySource(
            LICENSE_RESPONSE_PUBKEY_BASE64,
            true,
            new CryptoPP::Base64Decoder);
        publicKeySource.TransferTo(publicKeyBytes);
        publicKeyBytes.MessageEnd();

        CryptoPP::ed25519PublicKey publicKey;
        publicKey.Load(publicKeyBytes);
        CryptoPP::ed25519::Verifier verifier(publicKey);

        std::string signature;
        CryptoPP::StringSource signatureSource(
            signatureBase64,
            true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signature)));

        std::string signedMessage = "license-response:v1\nkey=" + key + "\nstatus=" + status;
        std::string combined = signedMessage + signature;
        CryptoPP::StringSource verificationSource(
            combined,
            true,
            new CryptoPP::SignatureVerificationFilter(
                verifier,
                NULL,
                CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION));
        return true;
    }
    catch (CryptoPP::Exception&) {
        return false;
    }
}

std::string keychecker() {
    std::string key;
    std::cout << "Enter Key: ";
    std::cin >> key;
    return key;
};

void auth() {
    std::string hostfile = "https://example.com/check-license"; // HTTPS endpoint that accepts POST field "key".
    std::string hot = keychecker();
    std::string result = PostKey(hostfile, hot);
    if (VerifySignedResponse(hot, result)) {
        std::cout << "Whitelisted Key\n"; //Success message.
    }
    else {
        std::cout << "Key Not Found\n";
        Sleep(10000);
        exit(10);
    };
};

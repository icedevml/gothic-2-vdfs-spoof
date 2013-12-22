#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <windows.h>
#include <stdio.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <string.h>
#include <map>

#include "spoof.h"
#include "sha1.h"

std::map<int, key_t> vdf_keys;

#ifdef DEBUG_FEATURES
void dump_key(key_t key) {
    char hexstring[41];
    sha1::toHexString(key, hexstring);
    std::cout << hexstring;
}
#endif

std::string strip_name(char* name) {
    std::string str(name);
    unsigned int pos = str.rfind("\\");
    if (pos != std::string::npos) {
        str = str.substr(pos+1);
    }
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

void crypt_buffer(char* buffer, unsigned int len,
                  key_t key, unsigned int initpos) {
    unsigned int pos = initpos % KEY_LEN;
    for(unsigned int i = 0; i < len; i++) {
        *buffer ^= key[pos];
        buffer++;
        pos++;
        if (pos >= KEY_LEN) {
            pos = 0;
        }
    }
}

bool check_key(int handle, key_t key) {
    unsigned char key_hash[KEY_LEN];
    unsigned char file_hash[KEY_LEN];
    if (vdf_fread(handle, (char*)file_hash, KEY_LEN) != KEY_LEN) {
#ifdef DEBUG_FEATURES
        std::cout << "-> KEY CHECK FAILED! (1)" << std::endl;
#endif
        return false;
    }
    sha1::calc(key, KEY_LEN, (key_t)key_hash);
    if (memcmp((const char*)key_hash, (const char*)file_hash, KEY_LEN) != 0) {
#ifdef DEBUG_FEATURES
        std::cout << "-> KEY CHECK FAILED! (2)" << std::endl;
#endif
        return false;
    }
    return true;
}

int DLL_EXPORT hook_vdf_fopen(char* name, int mode) {
    int handle = vdf_fopen(name, mode);

    if (handle >= 0) {
        // check for encrypted file header
        uint32_t magic;
        if (vdf_fread(handle, (char*)&magic, MAGIC_SIZE) == MAGIC_SIZE
				&& magic == MAGIC) {
            std::string base_name = strip_name(name);
            key_t key = new unsigned char[KEY_LEN];
#ifdef DEBUG_FEATURES
            std::cout << "decrypting " << base_name << std::endl;
#endif
            sha1::calc(base_name.c_str(), base_name.size(), key);
            if (!check_key(handle, key)) {
                std::string error_text = "GVC: KEY FAIL:";
                error_text += name;
                FatalAppExit(0, error_text.c_str());
                return -1;
            }
#ifdef DEBUG_FEATURES
            std::cout << "-> with key: ";
            dump_key(key);
            std::cout << std::endl;
#endif
            vdf_keys.insert(std::pair<int, key_t>(handle, key));
        } else {
#ifdef DEBUG_FEATURES
            std::cout << "open " << name << std::endl;
#endif
            vdf_fseek(handle, 0);
        }
    }

    return handle;
}

int DLL_EXPORT hook_vdf_fseek(int handle, long offset) {
    if (vdf_keys.find(handle) != vdf_keys.end()) {
        offset += MAGIC_SIZE+KEY_LEN;
    }

    return vdf_fseek(handle, offset);
}

int DLL_EXPORT hook_vdf_fclose(int handle) {
    if (vdf_keys.find(handle) != vdf_keys.end()) {
        delete[] vdf_keys[handle];
        vdf_keys.erase(handle);
    }

    return vdf_fclose(handle);
}

long DLL_EXPORT hook_vdf_fread(int handle, char* buffer, long len) {
    long result = vdf_fread(handle, buffer, len);
    if (vdf_keys.find(handle) != vdf_keys.end()) {
        long offset = vdf_ftell(handle)-len-MAGIC_SIZE-KEY_LEN;
        crypt_buffer(buffer, len, vdf_keys[handle], offset);
    }
    return result;
}

long DLL_EXPORT hook_vdf_ftell(int handle) {
    long result = vdf_ftell(handle);

    if (vdf_keys.find(handle) != vdf_keys.end()) {
        result -= MAGIC_SIZE+KEY_LEN;
    }

    return result;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH) {
        return 1;
    }

#ifdef DEBUG_FEATURES
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    std::cout.sync_with_stdio();
#endif

#ifdef WITH_GTOOLS
    LPWSTR* szArglist;
    int nArgs;

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist == NULL) {
        return 0;
    } else {
        for(int i = 0; i<nArgs; i++) {
            if (StrCmpW(szArglist[i], L"-gtools") == 0) {
                if (LoadLibrary("gtools.dll") == NULL) {
                    return 0;
                }
            } else if (StrCmpW(szArglist[i], L"-gtools-dev") == 0) {
                if (LoadLibrary("gtools-dev.dll") == NULL) {
                    return 0;
                }
            }
        }
    }

    LocalFree(szArglist);
#endif

    return 1;
}

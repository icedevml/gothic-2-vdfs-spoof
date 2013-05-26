#pragma once

#define MAGIC (unsigned int)(0xC0FFEE24)
#define KEY_LEN 20
typedef unsigned char* key_t;

#define DLL_IMPORT __declspec(dllimport)
#define DLL_EXPORT __declspec(dllexport)

extern "C" {
	int DLL_IMPORT vdf_fopen(char* name, int mode);
	int DLL_IMPORT vdf_fclose(int handle);
	long DLL_IMPORT vdf_fread(int handle, char* buffer, long len);
	long DLL_IMPORT vdf_ftell(int handle);
	int DLL_IMPORT vdf_fseek(int handle, long len);

	int DLL_EXPORT hook_vdf_fopen(char* name, int mode);
	int DLL_EXPORT hook_vdf_fseek(int handle, long offset);
	int DLL_EXPORT hook_vdf_fclose(int handle);
	long DLL_EXPORT hook_vdf_fread(int handle, char* buffer, long len);
	long DLL_EXPORT hook_vdf_ftell(int handle);
}
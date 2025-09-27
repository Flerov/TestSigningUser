#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <tchar.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <string>
#include <array>
#include <algorithm>

// ============================================================================
// Existing code kept intact below (symbol handling, PDB, etc.)
// ============================================================================

typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;


PBYTE ReadFullFileW(LPCWSTR fileName);
IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva);
PVOID PE_RVA_to_Addr(PE* pe, DWORD rva);
PE* PE_create(PVOID imageBase, BOOL isMemoryMapped);
VOID PE_destroy(PE* pe);
BOOL FileExistsW(LPCWSTR szPath);
BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize);
BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size);
BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size);
BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size);
symbol_ctx* LoadSymbolsFromPE(PE* pe);
symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path);
DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name);
void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb);
void CleanupSymbolHandler(HANDLE symHandle);
DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name);
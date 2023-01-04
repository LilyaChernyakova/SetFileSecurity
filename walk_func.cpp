#include <iostream>
#include <cstdio>
#include <aclapi.h>
#include <string>
#include <fstream>
#include <iterator>
#include <winbase.h>
#include <fileapi.h>
#include <tchar.h>
#include <winsvc.h>
#include <io.h>

using namespace std;

ACCESS_MODE AccessMode;

#define BUFSIZE MAX_PATH
#define SERVICE_NAME  _T("Protect Daemon")
#define SERVICE_FILENAME "ProtectDaemon.exe"

#define PROTECT_FILENAME "template.tbl"

PSID create_sid();                          // создает world SID
DWORD protect_file(LPTSTR);                 // защищает наш файл

int create_template(TCHAR *);
void protect_template_file(TCHAR *);
void unprotect_template_file(TCHAR *);

void find_mask_protect(char *, char *);     // обход файлов в папке
void search_dirs_protect(char *, char *);   // рекурсивный обход по папкам

int exists_test (const string&);
void replace(ostream& _o, istream& _i, const string &o, const string &n);

int protect_files(TCHAR *);
int unprotect_files(TCHAR *);

int check_pswd(string, TCHAR *);
int change_pswd(TCHAR *path_to_project_dir);

int service_install();
int service_remove();
int service_start(TCHAR*);
int service_stop();

// DENY добавляет запрет для группы "Все"
// SET устанавливает разрешение для группы "Все"
// REVOKE стирает все разрешающие записи для данной группы

int main(int argc, char *argv[])
{
    TCHAR path_to_project_dir[BUFSIZE];
    int dwRet = GetCurrentDirectory(BUFSIZE, path_to_project_dir);

    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);

    int c;
    cout << "Welcome to protect system! Choose the option (print a number from 1 to 5):\n"
            "[1]\tCreate a template file\n"
            "[2]\tProtect files using the templates\n"
            "[3]\tUnprotect files\n"
            "[4]\tChange password\n"
            "[5]\tExit\n";
    cin >> c;

    switch (c) {
        case 1:
            create_template(path_to_project_dir);
            break;
        case 2:
            protect_files(path_to_project_dir);
            // Если служба не запустилась, поставить защиту
            break;
        case 3:
            unprotect_files(path_to_project_dir);
            break;
        case 4:
            change_pswd(path_to_project_dir);
            break;
        case 5:
            return 0;
        default:
            cout << "Undefined option\n";
            break;
    }

    system("pause");
    return 0;
}

PSID create_sid() {
    PSID pEveryoneSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
            SECURITY_WORLD_SID_AUTHORITY;
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                                 SECURITY_WORLD_RID,
                                 0, 0, 0, 0, 0, 0, 0,
                                 &pEveryoneSID))
    {
        cout << "ERROR: create_sid\n";
    }
    return pEveryoneSID;
}
DWORD protect_file (LPTSTR pszObjName) {
    SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;                 // тип файла - объект
    LPTSTR pszTrustee = (LPTSTR) create_sid();                  // группа - все
    TRUSTEE_FORM TrusteeForm = TRUSTEE_IS_SID;                  // способ задания группы - по SID
    // для переименования нужен доступ на удаление, если его нет, то и переименовать файл будет нельзя
    // копирование невозможно запретить без запрета на открытие
    DWORD dwAccessRights = DELETE | GENERIC_READ;               // права
    DWORD dwInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;   // наследование

    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (!pszObjName)
        return ERROR_INVALID_PARAMETER;

    // Получить указатель на существующий DACL.
    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf( "GetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup;
    }

    // Инициализировать EXPLICIT_ACCESS структуру для новой ACE.
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)pszTrustee;

    // слить новый и старый ACL
    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetEntriesInAcl Error %u\n", dwRes );
        goto Cleanup;
    }

    // вставить новый ACL в DACL.
    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup;
    }

    Cleanup:

    if(pSD != NULL)
        LocalFree((HLOCAL) pSD);
    if(pNewDACL != NULL)
        LocalFree((HLOCAL) pNewDACL);

    return dwRes;
}

void unprotect_template_file(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);

    AccessMode = SET_ACCESS;
    protect_file(TEXT(path_to_protect_file));
    AccessMode = REVOKE_ACCESS;
    protect_file(TEXT(path_to_protect_file));
}

void protect_template_file(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);

    AccessMode = DENY_ACCESS;
    protect_file(TEXT(path_to_protect_file));
}

void find_mask_protect(char *Dir, char *Mask) {
    char buf[BUFSIZE]={0};
    sprintf(buf, "%s\\%s", Dir, Mask);

    WIN32_FIND_DATA FindFileData;
    HANDLE hf;
    hf=FindFirstFile(buf, &FindFileData);

    if (hf!=INVALID_HANDLE_VALUE)
    {
        do
        {
            sprintf(buf, "%s\\%s", Dir, FindFileData.cFileName);
            if (strcmp(FindFileData.cFileName,"..")!=0 && strcmp(FindFileData.cFileName,".")!=0) {
                // если это не родительский и не текущий каталог, задаём права
                protect_file(TEXT(buf));
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}
void search_dirs_protect(char *Dir, char *Mask) {
    find_mask_protect(Dir, Mask);
    char buf[BUFSIZE]={0};
    sprintf(buf, "%s\\%s", Dir, "*");

    WIN32_FIND_DATA FindFileData;
    HANDLE hf;
    hf=FindFirstFile(buf, &FindFileData);


    if (hf!=INVALID_HANDLE_VALUE)
    {
        do
        {
            sprintf(buf, "%s\\%s", Dir, FindFileData.cFileName);
            if (strcmp(FindFileData.cFileName,"..")!=0 && strcmp(FindFileData.cFileName,".")!=0) {
                // если это не додительский и не текущий каталог и это является папкой, выполняем в ней поиск
                if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    search_dirs_protect(buf, Mask);
                }
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}

int exists_test(const string& name) {
    char *filename = const_cast<char*>(name.c_str());
    if ((_access(filename, 0 )) != -1 )
        // файл существует
        return 1;
    return 0;
}

void replace(ostream& _o, istream& _i, const string& o, const string& n){
    string::size_type p = 0;
    string s;
    while(getline(_i, s) && !_i.fail()){
        p = 0;
        while((p = s.find(o, p)) != string::npos){
            s.replace(s.begin() + p, s.begin() + (p + o.length()), n);
            p += n.length();
        }
        _o << s << endl;
    }
    _o.flush();
}

int check_pswd(string pswd, TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);

    string inp;
    ifstream file;
    file.open(path_to_protect_file);
    getline(file, inp);
    file.close();

    string tmp_pswd = to_string(hash<string>()(pswd));
    return tmp_pswd.compare(inp);
}
int create_template(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file))
    {
        cout << "Let's create file template.tbl!\n";
        string inp;
        ofstream template_file;
        template_file.open(path_to_protect_file);

        // ошибка создания файла template.tbl
        if (!(template_file.is_open())) {
            cout << "ERROR: Could not create template file\n";
            return -1;
        }

        cout << "Create a password\n";
        cin >> inp;
        size_t hash_value = hash<string>()(inp);
        template_file << hash_value << "\n";

        cout << "Enter file name/mask or E for Exit\n";

        cin >> inp;

        while(strcmp(const_cast<char*>(inp.c_str()), "E") != 0) {
            if (strlen(path_to_project_dir) + inp.length() >= MAX_PATH) {
                cout << "Length limit surpassed. Please try again\n";
            }
            else template_file << inp << "\n";
            cin >> inp;
        }

        template_file.close();
        protect_template_file(path_to_project_dir);
        cout << "File template.tbl created and protected.\n";
    }
    else
        cout << "File template.tbl exists\n";
    return 0;
}
int protect_files(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.tbl does not exist. Create it.\n";
        return 0;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return -1;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hService && GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return -1;
    }
    else if (hService) {
        cout << "ERROR: Files are already protected\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return 0;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    unprotect_template_file(path_to_project_dir);

    string pswd;
    cout << "Enter the password\n";
    cin >> pswd;
    if (check_pswd(pswd, path_to_project_dir)) {
        cout << "Wrong password\n";
        protect_template_file(path_to_project_dir);
        return 0;
    }

    string inp;
    ifstream file;
    file.open(path_to_protect_file);
    if (!file.is_open()) {
        cout << "ERROR: Could not open template file\n";
        protect_template_file(path_to_project_dir);
        return -1;
    }

    int i = 0;
    while(getline(file, inp)){
        char* inp_chr;
        if (i++ != 0) {
            inp_chr = const_cast<char*>(inp.c_str());
            AccessMode = DENY_ACCESS;
            search_dirs_protect(path_to_project_dir, inp_chr);
        }
    }
    file.close();
    service_install();
    service_start(path_to_project_dir);
    return 0;
}
int unprotect_files(TCHAR *path_to_project_dir) {
    service_stop();
    service_remove();

    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.tbl does not exist. Create it.\n";
        return 0;
    }
    unprotect_template_file(path_to_project_dir);

    string pswd;
    cout << "Enter the password\n";
    cin >> pswd;
    if (check_pswd(pswd, path_to_project_dir)) {
        cout << "Wrong password\n";
        protect_template_file(path_to_project_dir);
        return 0;
    }

    string inp;
    ifstream file;
    file.open(path_to_protect_file);
    if (!file.is_open()) {
        cout << "ERROR: Could not open template file\n";
        protect_template_file(path_to_project_dir);
        return -1;
    }

    int i = 0;
    while(getline(file, inp)){
        char* inp_chr;
        if (i++ != 0) {
            inp_chr = const_cast<char*>(inp.c_str());
            AccessMode = SET_ACCESS;
            search_dirs_protect(path_to_project_dir, inp_chr);
            AccessMode = REVOKE_ACCESS;
            search_dirs_protect(path_to_project_dir, inp_chr);
        }
    }
    file.close();
    protect_template_file(path_to_project_dir);
    return 0;
}
int change_pswd(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.tbl does not exist. Create it.\n";
        return 0;
    }
    unprotect_template_file(path_to_project_dir);

    string pswd;
    cout << "Enter the password\n";
    cin >> pswd;
    if (check_pswd(pswd, path_to_project_dir)) {
        cout << "Wrong password\n";
        protect_template_file(path_to_project_dir);
        return 0;
    }

    string old_pswd;
    ifstream file;
    file.open(path_to_protect_file);
    if (!file.is_open()) {
        cout << "ERROR: Could not open template file\n";
        protect_template_file(path_to_project_dir);
        return -1;
    }

    getline(file, old_pswd);
    file.close();

    string new_pswd;
    cout << "Enter a new password\n";
    cin >> new_pswd;
    new_pswd = to_string(hash<string>()(new_pswd));

    ifstream fin(path_to_protect_file);
    ofstream fout(".\\tmp.tbl");
    replace(fout, fin, old_pswd, new_pswd);
    fout.close();
    fin.close();
    string path = path_to_protect_file;
    remove(path.c_str());
    rename(".\\tmp.tbl", path_to_protect_file);
    protect_template_file(path_to_project_dir);
    return 0;
}

int service_install() {
    TCHAR servicePath[BUFSIZE];
    int dwRet = GetCurrentDirectory(BUFSIZE, servicePath);
    sprintf(servicePath, "%s\\%s", servicePath, const_cast<char*>(SERVICE_FILENAME));

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if(!hSCManager) {
        cout << "ERROR: Cannot open Service Control Manager\n";
        return -1;
    }

    SC_HANDLE hService = CreateService(
            hSCManager,
            SERVICE_NAME,
            SERVICE_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            servicePath,
            NULL, NULL, NULL, NULL, NULL
    );

    if(!hService) {
        int err = GetLastError();
        switch(err) {
            case ERROR_ACCESS_DENIED:
                cout << "ERROR: ERROR_ACCESS_DENIED\n";
                break;
            case ERROR_CIRCULAR_DEPENDENCY:
                cout << "ERROR: ERROR_CIRCULAR_DEPENDENCY\n";
                break;
            case ERROR_DUPLICATE_SERVICE_NAME:
                cout << "ERROR: ERROR_DUPLICATE_SERVICE_NAME\n";
                break;
            case ERROR_INVALID_HANDLE:
                cout << "ERROR: ERROR_INVALID_HANDLE\n";
                break;
            case ERROR_INVALID_NAME:
                cout << "ERROR: ERROR_INVALID_NAME\n";
                break;
            case ERROR_INVALID_PARAMETER:
                cout << "ERROR: ERROR_INVALID_PARAMETER\n";
                break;
            case ERROR_INVALID_SERVICE_ACCOUNT:
                cout << "ERROR: ERROR_INVALID_SERVICE_ACCOUNT\n";
                break;
            case ERROR_SERVICE_EXISTS:
                cout << "ERROR: ERROR_SERVICE_EXISTS\n";
                break;
            default:
                cout << "ERROR: Undefined\n";
        }
        CloseServiceHandle(hSCManager);
        return -1;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

int service_remove() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!hSCManager) {
        cout << "ERROR: Cannot open Service Control Manager\n";
        return -1;
    }
    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if(!hService && GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        cout << "ERROR: Cannot remove service\n";
        CloseServiceHandle(hSCManager);
        return -1;
    }
    else if (!hService) {
        cout << "ERROR: Service does not exist\n";
    }

    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

int service_start(TCHAR* dirPath) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START);
    if(!StartService(hService, 1, (LPCSTR*)&dirPath)) {
        cout << "ERROR: Cannot start the service\n";
        CloseServiceHandle(hSCManager);
        return -1;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

int service_stop() {
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return -1;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return -1;
    }

    if ( !QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded ) )
    {
        printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        goto stop_cleanup;
    }

    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
        printf("Service is already stopped.\n");
        goto stop_cleanup;
    }

    if ( !ControlService(
            hService,
            SERVICE_CONTROL_STOP,
            (LPSERVICE_STATUS) &ssp ) )
    {
        printf( "ControlService failed (%d)\n", GetLastError() );
        goto stop_cleanup;
    }

    stop_cleanup:
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}
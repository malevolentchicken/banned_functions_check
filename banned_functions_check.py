import pefile

inspect_file = "test.exe"

file = pefile.PE(inspect_file)

# This list was extracted from banned.h
banned_funcs = ["strcpy"," strcpyA"," strcpyW"," wcscpy"," _tcscpy"," _mbscpy"," StrCpy"," StrCpyA"," StrCpyW"," lstrcpy"," lstrcpyA"," lstrcpyW"," _tccpy"," _mbccpy"," _ftcscpy"," strcat"," strcatA"," strcatW"," wcscat"," _tcscat"," _mbscat"," StrCat"," StrCatA"," StrCatW"," lstrcat"," lstrcatA"," lstrcatW"," StrCatBuff"," StrCatBuffA"," StrCatBuffW"," StrCatChainW"," _tccat"," _mbccat"," _ftcscat"," wvsprintf"," wvsprintfA"," wvsprintfW"," vsprintf"," _vstprintf"," vswprintf"," strncpy"," wcsncpy"," _tcsncpy"," _mbsncpy"," _mbsnbcpy"," StrCpyN"," StrCpyNA"," StrCpyNW"," StrNCpy"," strcpynA"," StrNCpyA"," StrNCpyW"," lstrcpyn"," lstrcpynA"," lstrcpynW"," strncat"," wcsncat"," _tcsncat"," _mbsncat"," _mbsnbcat"," StrCatN"," StrCatNA"," StrCatNW"," StrNCat"," StrNCatA"," StrNCatW"," lstrncat"," lstrcatnA"," lstrcatnW"," lstrcatn"," IsBadWritePtr"," IsBadHugeWritePtr"," IsBadReadPtr"," IsBadHugeReadPtr"," IsBadCodePtr"," IsBadStringPtr"," gets"," _getts"," _gettws"," RtlCopyMemory"," CopyMemory"," wnsprintf"," wnsprintfA"," wnsprintfW"," sprintfW"," sprintfA"," wsprintf"," wsprintfW"," wsprintfA"," sprintf"," swprintf"," _stprintf"," _snwprintf"," _snprintf"," _sntprintf"," _vsnprintf"," vsnprintf"," _vsnwprintf"," _vsntprintf"," wvnsprintf"," wvnsprintfA"," wvnsprintfW"," strtok"," _tcstok"," wcstok"," _mbstok"," makepath"," _tmakepath"," _makepath"," _wmakepath"," _splitpath"," _tsplitpath"," _wsplitpath"," scanf"," wscanf"," _tscanf"," sscanf"," swscanf"," _stscanf"," snscanf"," snwscanf"," _sntscanf"," _itoa"," _itow"," _i64toa"," _i64tow"," _ui64toa"," _ui64tot"," _ui64tow"," _ultoa"," _ultot"," _ultow"," CharToOem"," CharToOemA"," CharToOemW"," OemToChar"," OemToCharA"," OemToCharW"," CharToOemBuffA"," CharToOemBuffW"," alloca"," _alloca"," strlen"," wcslen"," _mbslen"," _mbstrlen"," StrLen"," lstrlen"," ChangeWindowMessageFilter"]
banned_imports = []

# Parse through the Import Table.
for entry in file.DIRECTORY_ENTRY_IMPORT:    
    dll_name = entry.dll.decode('utf-8')
    print ("\n[*] " + dll_name + " imports:")

    # For each import listed.
    for func in entry.imports:        
        print("%s at 0x%08x" % (func.name.decode('utf-8'), func.address))        
        
        # If a function name is contained in the banned_funcs list.
        if func.name.decode('utf-8') in banned_funcs:
            
            # Creates a list of tuples.
            banned_imports.append((dll_name, func.name.decode('utf-8'), func.address))

# If banned functions were found to be imported.
if banned_imports != " ": 
    
    print ("----------------------- Banned Functions Found Imported -----------------------")
    print ("Importing File: " + inspect_file)

    for func in banned_imports:        
        print ("Library Name: " + func[0]) # Print DLL Name
        print ("Function Name: " + func[1]) # Print Function Name        
        print("%s 0x%08x" % ("Function Address: ", func[2])) # Print Import Address

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall"
)

const (
	IMAGE_DOS_SIGNATURE    = 0x5A4D
	IMAGE_NT_SIGNATURE     = 0x00004550
	IMAGE_SCN_MEM_EXECUTE  = 0x20000000
	IMAGE_SCN_CNT_CODE     = 0x00000020
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READONLY          = 0x02
	SECTION_MAP_READ       = 0x0004
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           [2]uintptr
	InMemoryOrderLinks         [2]uintptr
	InInitializationOrderLinks [2]uintptr
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  [2]uintptr
	TimeDateStamp              uint32
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        uintptr
	InLoadOrderModuleList           [2]uintptr
	InMemoryOrderModuleList         [2]uintptr
	InInitializationOrderModuleList [2]uintptr
	EntryInProgress                 uintptr
	ShutdownInProgress              uint8
	ShutdownThreadId                uintptr
}

type PEB struct {
	InheritedAddressSpace      uint8
	ReadImageFileExecOptions   uint8
	BeingDebugged              uint8
	BitField                   uint8
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        uintptr
	ProcessParameters          uintptr
	SubSystemData              uintptr
	ProcessHeap                uintptr
	FastPebLock                uintptr
	AtlThunkSListPtr           uintptr
	IFEOKey                    uintptr
	CrossProcessFlags          uint32
	UserSharedInfoPtr          uintptr
	SystemReserved             uint32
	AtlThunkSListPtr32         uint32
	ApiSetMap                  uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length             uint32
	RootDirectory      uintptr
	ObjectName         uintptr
	Attributes         uint32
	SecurityDescriptor uintptr
	SecurityQualityOfService uintptr
}

func main() {
	winapi.ApplyAllPatches()
	fmt.Println("Starting NTDLL unhooking process...")
	
	// Step 1: Get current ntdll base address using PEB
	currentNtdllBase, err := getCurrentNtdllBase()
	if err != nil {
		log.Fatalf("Failed to get current ntdll base: %v", err)
	}
	fmt.Printf("Current ntdll base: 0x%x\n", currentNtdllBase)
	
	// Step 2: Load fresh ntdll from KnownDlls
	fmt.Printf("About to call loadFreshNtdll()...\n")
	freshNtdllBase, freshNtdllSize, err := loadFreshNtdll()
	fmt.Printf("loadFreshNtdll returned: base=0x%x, size=%d, err=%v\n", freshNtdllBase, freshNtdllSize, err)
	
	if err != nil {
		log.Fatalf("Failed to load fresh ntdll: %v", err)
	}
	
	fmt.Printf("About to set up defer...\n")
	defer func() {
		fmt.Printf("Defer cleanup called\n")
		regionSize := uintptr(freshNtdllSize)
		winapi.NtFreeVirtualMemory(getCurrentProcess(), &freshNtdllBase, &regionSize, 0x8000) // MEM_RELEASE
	}()
	fmt.Printf("Defer set up successfully\n")
	fmt.Printf("Fresh ntdll loaded at: 0x%x (size: %d)\n", freshNtdllBase, freshNtdllSize)
	
	// Step 3: Find and copy the .text section
	fmt.Printf("About to call copyTextSection with currentBase=0x%x, freshBase=0x%x\n", currentNtdllBase, freshNtdllBase)
	
	if currentNtdllBase == 0 {
		log.Fatalf("currentNtdllBase is 0!")
	}
	if freshNtdllBase == 0 {
		log.Fatalf("freshNtdllBase is 0!")
	}
	
	err = copyTextSection(currentNtdllBase, freshNtdllBase)
	if err != nil {
		log.Fatalf("Failed to copy text section: %v", err)
	}
	
	fmt.Println("NTDLL unhooking completed successfully!")
}

func GetPEB() uintptr 

func getCurrentProcess() uintptr {
	return ^uintptr(0) // -1 as uintptr, which is the handle for current process
}

// UTF16ToString converts a UTF-16 encoded slice to a Go string
func UTF16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	result := make([]rune, len(s))
	for i, v := range s {
		result[i] = rune(v)
	}
	return string(result)
}

func getCurrentNtdllBase() (uintptr, error) {
	// Use the assembly function to get PEB
	pebAddr := GetPEB()
	if pebAddr == 0 {
		return 0, fmt.Errorf("failed to get PEB address")
	}
	
	peb := (*PEB)(unsafe.Pointer(pebAddr))
	if peb.Ldr == 0 {
		return 0, fmt.Errorf("PEB.Ldr is null")
	}
	
	ldr := (*PEB_LDR_DATA)(unsafe.Pointer(peb.Ldr))
	
	// Walk the InLoadOrderModuleList to find ntdll
	head := uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList[0]))
	current := ldr.InLoadOrderModuleList[0]
	
	for current != head {
		entry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(current))
		
		// Get the DLL name
		nameBuffer := (*uint16)(unsafe.Pointer(entry.BaseDllName.Buffer))
		nameLen := int(entry.BaseDllName.Length / 2)
		
		if nameBuffer != nil && nameLen > 0 {
			name := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				name[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(nameBuffer)) + uintptr(i*2)))
			}
			
			dllName := UTF16ToString(name)
			if dllName == "ntdll.dll" {
				return entry.DllBase, nil
			}
		}
		
		current = entry.InLoadOrderLinks[0]
	}
	
	return 0, fmt.Errorf("ntdll.dll not found in PEB")
}

// initUnicodeString mimics the behavior of the Windows RtlInitUnicodeString function.
func initUnicodeString(us *UNICODE_STRING, s []uint16) {
	// Find length of null-terminated string
	strLen := 0
	for strLen < len(s) && s[strLen] != 0 {
		strLen++
	}
	us.Length = uint16(strLen * 2)
	us.MaximumLength = uint16(len(s) * 2)
	if len(s) > 0 {
		us.Buffer = &s[0]
	}
}

func loadFreshNtdll() (uintptr, uint32, error) {
	// Load fresh ntdll from KnownDlls directory - much simpler approach!
	fmt.Printf("Loading fresh ntdll from KnownDlls directory...\n")

	// Create unicode string for KnownDlls\ntdll.dll
	var unicodeString UNICODE_STRING
	ntdllPath := [...]uint16{
		'\\', 'K', 'n', 'o', 'w', 'n', 'D', 'l', 'l', 's', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0,
	}
	initUnicodeString(&unicodeString, ntdllPath[:])

	// Set up object attributes exactly like InitializeObjectAttributes macro
	var objAttr OBJECT_ATTRIBUTES
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.RootDirectory = 0 // NULL in C
	objAttr.ObjectName = uintptr(unsafe.Pointer(&unicodeString))
	objAttr.Attributes = 0x40 // OBJ_CASE_INSENSITIVE
	objAttr.SecurityDescriptor = 0 // NULL in C
	objAttr.SecurityQualityOfService = 0 // NULL in C, explicitly set by macro

	// Open section to KnownDlls\ntdll.dll using a direct syscall.
	var sectionHandle uintptr
	status, err := winapi.DirectSyscall("NtOpenSection",
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_MAP_READ,
		uintptr(unsafe.Pointer(&objAttr)))

	if err != nil {
		return 0, 0, fmt.Errorf("NtOpenSection direct syscall failed: %v", err)
	}

	if status != 0 {
		return 0, 0, fmt.Errorf("NtOpenSection failed with status: 0x%x", status)
	}

	fmt.Printf("Successfully opened section handle: 0x%x\n", sectionHandle)

	// Map the section into our address space using the new wrapper function.
	// We pass 0 for size, so the entire section is mapped.
	baseAddress, viewSize, err := ntMapViewOfSection(sectionHandle, 0)
	if err != nil {
		winapi.NtClose(sectionHandle)
		return 0, 0, fmt.Errorf("mapping section failed: %w", err)
	}

	// Only defer the close after successful mapping
	defer winapi.NtClose(sectionHandle)

	// The check for baseAddress == 0 is now inside ntMapViewOfSection
	fmt.Printf("Successfully mapped clean ntdll from KnownDlls at: 0x%x (size: %d)\n", baseAddress, viewSize)

	return baseAddress, uint32(viewSize), nil
}

func createSuspendedProcess() (uintptr, error) {
	// Create a suspended process using NtCreateProcess + NtCreateThreadEx
	var processHandle uintptr
	
	// Set up object attributes
	var objAttr OBJECT_ATTRIBUTES
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.RootDirectory = 0
	objAttr.ObjectName = 0
	objAttr.Attributes = 0
	objAttr.SecurityDescriptor = 0
	objAttr.SecurityQualityOfService = 0
	
	// Create process object
	status, err := winapi.NtCreateProcess(
		&processHandle,
		0x1FFFFF, // PROCESS_ALL_ACCESS
		uintptr(unsafe.Pointer(&objAttr)), // ObjectAttributes
		getCurrentProcess(), // Parent process
		false,    // InheritObjectTable
		0,        // SectionHandle (0 means create new address space)
		0,        // DebugPort
		0)        // ExceptionPort
	
	if err != nil {
		return 0, fmt.Errorf("NtCreateProcess failed: %v", err)
	}
	
	if status != 0 {
		return 0, fmt.Errorf("NtCreateProcess failed with status: 0x%x", status)
	}
	
	// Now create a suspended thread in the process to load ntdll
	var threadHandle uintptr
	var clientId [2]uintptr // CLIENT_ID structure
	
	status, err = winapi.NtCreateThreadEx(
		&threadHandle,
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,         // ObjectAttributes (NULL)
		processHandle, // ProcessHandle
		0,         // StartRoutine (NULL for now)
		0,         // Argument
		1,         // CreateFlags (THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 1)
		0,         // ZeroBits
		0,         // StackSize
		0,         // MaximumStackSize
		uintptr(unsafe.Pointer(&clientId))) // ClientId
	
	if err != nil {
		// Clean up process handle if thread creation fails
		winapi.NtTerminateProcess(processHandle, 0)
		return 0, fmt.Errorf("NtCreateThreadEx failed: %v", err)
	}
	
	if status != 0 {
		// Clean up process handle if thread creation fails
		winapi.NtTerminateProcess(processHandle, 0)
		return 0, fmt.Errorf("NtCreateThreadEx failed with status: 0x%x", status)
	}
	
	// Close the thread handle since we only need the process
	winapi.NtClose(threadHandle)
	
	return processHandle, nil
}

func getRemoteNtdllInfo(processHandle uintptr) (uintptr, uint32, error) {
	// Get the PEB address of the remote process
	var pbi ProcessBasicInformation
	var returnLength uintptr
	
	status, err := winapi.NtQueryInformationProcess(
		processHandle,
		0, // ProcessBasicInformation
		unsafe.Pointer(&pbi),
		unsafe.Sizeof(pbi),
		&returnLength)
	
	if err != nil {
		return 0, 0, fmt.Errorf("NtQueryInformationProcess failed: %v", err)
	}
	
	if status != 0 {
		return 0, 0, fmt.Errorf("NtQueryInformationProcess failed with status: 0x%x", status)
	}
	
	// Read the PEB from remote process
	var remotePeb PEB
	var bytesRead uintptr
	
	status, err = winapi.NtReadVirtualMemory(
		processHandle,
		pbi.PebBaseAddress,
		unsafe.Pointer(&remotePeb),
		unsafe.Sizeof(remotePeb),
		&bytesRead)
	
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read remote PEB: %v", err)
	}
	
	// Read the PEB_LDR_DATA from remote process
	var remoteLdr PEB_LDR_DATA
	status, err = winapi.NtReadVirtualMemory(
		processHandle,
		remotePeb.Ldr,
		unsafe.Pointer(&remoteLdr),
		unsafe.Sizeof(remoteLdr),
		&bytesRead)
	
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read remote LDR: %v", err)
	}
	
	// Walk the remote InLoadOrderModuleList to find ntdll
	head := remotePeb.Ldr + unsafe.Offsetof(remoteLdr.InLoadOrderModuleList)
	current := remoteLdr.InLoadOrderModuleList[0]
	
	for current != head {
		var entry LDR_DATA_TABLE_ENTRY
		status, err = winapi.NtReadVirtualMemory(
			processHandle,
			current,
			unsafe.Pointer(&entry),
			unsafe.Sizeof(entry),
			&bytesRead)
		
		if err != nil {
			return 0, 0, fmt.Errorf("failed to read LDR entry: %v", err)
		}
		
		// Read the DLL name
		if entry.BaseDllName.Buffer != nil && entry.BaseDllName.Length > 0 {
			nameLen := int(entry.BaseDllName.Length / 2)
			nameBuffer := make([]uint16, nameLen)
			
			status, err = winapi.NtReadVirtualMemory(
				processHandle,
				uintptr(unsafe.Pointer(entry.BaseDllName.Buffer)),
				unsafe.Pointer(&nameBuffer[0]),
				uintptr(entry.BaseDllName.Length),
				&bytesRead)
			
			if err == nil {
				dllName := UTF16ToString(nameBuffer)
				if dllName == "ntdll.dll" {
					return entry.DllBase, entry.SizeOfImage, nil
				}
			}
		}
		
		current = entry.InLoadOrderLinks[0]
		
		// Prevent infinite loops
		if current == 0 {
			break
		}
	}
	
	return 0, 0, fmt.Errorf("ntdll.dll not found in remote process")
}

type ProcessBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress              uintptr
	AffinityMask                uintptr
	BasePriority                uintptr
	UniqueProcessId             uintptr
	InheritedFromUniqueProcessId uintptr
}

func copyTextSection(currentBase, freshBase uintptr) error {
	fmt.Printf("copyTextSection called: currentBase=0x%x, freshBase=0x%x\n", currentBase, freshBase)
	
	// We need to get the fresh ntdll as a byte slice to use with PE library
	// First, let's get the size by parsing DOS header
	fmt.Printf("Reading DOS header from freshBase...\n")
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(freshBase))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return fmt.Errorf("invalid DOS signature in fresh ntdll: 0x%x", dosHeader.E_magic)
	}
	fmt.Printf("DOS header valid, e_lfanew=0x%x\n", dosHeader.E_lfanew)
	
	fmt.Printf("Reading NT headers...\n")
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(freshBase + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return fmt.Errorf("invalid NT signature in fresh ntdll: 0x%x", ntHeaders.Signature)
	}
	
	// Get the image size from optional header
	imageSize := ntHeaders.OptionalHeader.SizeOfImage
	fmt.Printf("Image size: %d bytes\n", imageSize)
	
	// Let's just parse it directly from disk instead of using the allocated memory
	// Read the file again
	fileData, err := os.ReadFile("C:\\Windows\\System32\\ntdll.dll")
	if err != nil {
		return fmt.Errorf("failed to re-read ntdll: %v", err)
	}
	
	fmt.Printf("Re-read file data: %d bytes\n", len(fileData))
	
	// Parse fresh ntdll with PE library using original file data
	reader := bytes.NewReader(fileData)
	freshPE, err := pe.NewFile(reader)
	if err != nil {
		return fmt.Errorf("failed to parse fresh ntdll PE: %v", err)
	}
	defer freshPE.Close()
	
	fmt.Printf("PE parsed successfully\n")
	
	// Find .text section in fresh PE
	var textSection *pe.Section
	for _, section := range freshPE.Sections {
		if section.Name == ".text" {
			textSection = section
			break
		}
	}
	
	if textSection == nil {
		return fmt.Errorf(".text section not found in fresh ntdll")
	}
	
	fmt.Printf("Found .text section: VirtualAddress=0x%x, Size=0x%x\n", 
		textSection.VirtualAddress, textSection.Size)
	
	// Read the .text section data from fresh PE
	textData, err := textSection.Data()
	if err != nil {
		return fmt.Errorf("failed to read .text section data: %v", err)
	}
	
	// Calculate target address in current ntdll
	currentTextAddr := currentBase + uintptr(textSection.VirtualAddress)
	textSize := uintptr(len(textData))
	
	// Change protection to allow writing
	var oldProtect uintptr
	status, err := winapi.NtProtectVirtualMemory(
		getCurrentProcess(),
		&currentTextAddr,
		&textSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtect)
	
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory failed: %v", err)
	}
	
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed (making writable): 0x%x", status)
	}

	// Copy the fresh .text section over the current one using NtWriteVirtualMemory, with retry logic.
	var bytesWritten uintptr
	const maxRetries = 5
	const retryDelay = 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		status, err = winapi.NtWriteVirtualMemory(
			getCurrentProcess(),
			currentTextAddr,
			unsafe.Pointer(&textData[0]),
			textSize,
			&bytesWritten)

		// Break on success
		if err == nil && status == 0 && bytesWritten == textSize {
			break
		}

		// If not the last attempt, print a message and wait
		if i < maxRetries-1 {
			fmt.Printf("NtWriteVirtualMemory attempt %d/%d failed: status=0x%x, bytesWritten=%d, err=%v. Retrying in %v...\n", i+1, maxRetries, status, bytesWritten, err, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	// After the loop, perform final checks for error conditions
	if err != nil {
		return fmt.Errorf("NtWriteVirtualMemory failed after %d retries: %v", maxRetries, err)
	}
	if status != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed after %d retries with status: 0x%x", maxRetries, status)
	}
	if bytesWritten != textSize {
		return fmt.Errorf("NtWriteVirtualMemory only wrote %d of %d bytes after %d retries", bytesWritten, textSize, maxRetries)
	}

	fmt.Printf("Copied %d bytes from fresh .text section (wrote %d bytes)\n", textSize, bytesWritten)
	
	// Restore original protection
	status, err = winapi.NtProtectVirtualMemory(
		getCurrentProcess(),
		&currentTextAddr,
		&textSize,
		oldProtect,
		&oldProtect)
	
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory failed: %v", err)
	}
	
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed (restoring protection): 0x%x", status)
	}
	
	return nil
}

func ntMapViewOfSection(sectionHandle uintptr, sizeOfImage uint32) (uintptr, uintptr, error) {
	const maxRetries = 10
	const baseDelay = 10 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		var bAddress uintptr
		// When sizeOfImage is 0, viewSize will be 0, telling NtMapViewOfSection to map the entire section.
		// The kernel will then populate viewSize with the actual mapped size.
		viewSize := uintptr(sizeOfImage)

		if attempt > 0 {
			delay := time.Duration(attempt) * baseDelay
			time.Sleep(delay)
		}

		status, err := winapi.NtMapViewOfSection(
			sectionHandle,
			getCurrentProcess(),
			&bAddress,
			0,
			0,
			nil,
			&viewSize,
			2, // ViewShare
			0,
			PAGE_READONLY)

		if err != nil {
			return 0, 0, fmt.Errorf("NtMapViewOfSection failed: %w", err)
		}

		// A status check for NTSTATUS should check for failure codes (MSB is 1).
		// Warnings (like STATUS_IMAGE_NOT_AT_BASE) are not failures.
		if status >= 0x80000000 {
			return 0, 0, fmt.Errorf("NtMapViewOfSection failed with NTSTATUS: 0x%x", status)
		}

		if bAddress != 0 {
			return bAddress, viewSize, nil
		}

		if attempt == maxRetries-1 {
			return 0, 0, fmt.Errorf("NtMapViewOfSection returned NULL base address after %d attempts", maxRetries)
		}
	}

	return 0, 0, fmt.Errorf("unexpected exit from retry loop")
}
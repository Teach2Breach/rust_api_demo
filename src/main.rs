// Standard library imports
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;

// WinAPI imports
use winapi::ctypes::c_void;
use winapi::shared::{
    basetsd::{PSIZE_T, SIZE_T, ULONG_PTR},
    ntdef::{HANDLE, NTSTATUS, PULONG, PVOID, ULONG},
};
use winapi::um::{
    errhandlingapi::GetLastError,
    memoryapi::{VirtualAlloc, VirtualProtect},
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, RTL_OSVERSIONINFOW},
};

pub fn main() {
    // in this program, we will demonstrate all the various ways to make windows API calls in rust

    loop {
        println!("\nChoose a method to make Windows API calls (or 0 to exit):");
        println!("1. Using the winapi crate");
        println!("2. Using ntapi crate");
        println!("3. Using GetProcAddress and GetModuleHandleA to get the function pointer and call the API");
        println!("4. Using LdrGetProcedureAddress and LdrGetDllHandle to get the function pointer and call the API");
        println!("5. Using noldr (PEB walk) to get the function pointer and call the API");
        println!(
            "6. Copy ntdll.dll to memory and locate functions in it using the ntdll exports table"
        );
        println!(
            "7. Copy ntdll from memory to a new buffer in memory and get the version of the system"
        );
        //dinvoke_rs is currently using an old version of windows crate (0.51 vs 0.58) which causes a lot of issues with HANDLEs
        //println!("8. Using dinvoke_rs to make indirect syscalls");
        println!("99. Get the version of ntdll.dll");

        print!("Enter the number of the method you want to use: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice: u32 = input.trim().parse().unwrap_or(0);

        match choice {
            0 => break,
            1 => use_winapi(),
            2 => use_ntapi(),
            3 => use_getprocaddress(),
            4 => use_ldrgetprocedureaddress(),
            5 => noldr_ntapi(),
            6 => nt_in_memory(),
            7 => mem_to_mem(),
            //8 => use_dinvoke_rs(),
            99 => get_ntdll_version(),
            // ... (other cases)
            _ => println!("Invalid choice. Please select a number between 0 and 7."),
        }

        println!("\nPress Enter to continue...");
        io::stdin().read_line(&mut String::new()).unwrap();
    }

    println!("Exiting the program.");
}

fn use_winapi() {
    //1. using the winapi crate
    //first we need to add the winapi crate to our dependencies
    //then we need to add the following to our Cargo.toml file:
    // winapi = { version = "0.3", features = ["winuser"] }
    //then we need to add the following to our source code:
    use winapi::um::winuser::MessageBoxA;
    use winapi::um::winuser::MB_OK;

    //now we need to create a function that will use the winapi crate to make a windows API call
    //we will use the MessageBoxA function to display a message box
    //the MessageBoxA function is used to display a message box with a title and a message

    //call the MessageBoxA function
    unsafe {
        MessageBoxA(
            null_mut(),
            "Hello, world!\0".as_ptr() as *const i8,
            "My first window\0".as_ptr() as *const i8,
            MB_OK,
        );
    }
}

fn use_ntapi() {
    use chrono;
    use ntapi::ntexapi::NtQuerySystemTime;
    use std::time::{Duration, UNIX_EPOCH};
    use winapi::shared::ntdef::LARGE_INTEGER;
    use winapi::shared::ntdef::NTSTATUS;
    use winapi::shared::ntdef::NT_SUCCESS;

    let mut system_time: LARGE_INTEGER = unsafe { std::mem::zeroed() };

    let status: NTSTATUS = unsafe { NtQuerySystemTime(&mut system_time) };

    if NT_SUCCESS(status) {
        // Convert Windows file time (100-nanosecond intervals since January 1, 1601) to Unix timestamp
        let windows_ticks = unsafe { system_time.QuadPart() };
        let unix_time = windows_ticks / 10_000_000 - 11_644_473_600;

        let system_time = UNIX_EPOCH + Duration::from_secs(unix_time as u64);
        let datetime: chrono::DateTime<chrono::Local> = system_time.into();

        println!("System time successfully retrieved using NtQuerySystemTime:");
        println!(
            "Current date and time: {}",
            datetime.format("%Y-%m-%d %H:%M:%S")
        );
    } else {
        println!("Failed to query system time. Status: {:#x}", status);
    }
}

// 3. Using GetProcAddress and GetModuleHandleA to get the function pointer and call the API
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::winuser::MB_OK;

fn use_getprocaddress() {
    // Get the handle to user32.dll
    let user32_dll = unsafe { GetModuleHandleA("user32.dll\0".as_ptr() as *const i8) };
    if user32_dll.is_null() {
        println!("Failed to get handle to user32.dll");
        return;
    }

    // Get the address of the MessageBoxA function
    let message_box_a_addr =
        unsafe { GetProcAddress(user32_dll, "MessageBoxA\0".as_ptr() as *const i8) };
    if message_box_a_addr.is_null() {
        println!("Failed to get address of MessageBoxA");
        return;
    }

    // Define the function type for MessageBoxA
    type MessageBoxAFn = unsafe extern "system" fn(*mut c_void, *const i8, *const i8, u32) -> i32;

    // Cast the function pointer
    let message_box_a: MessageBoxAFn = unsafe { std::mem::transmute(message_box_a_addr) };

    // Call the MessageBoxA function
    unsafe {
        message_box_a(
            null_mut(),
            "Hello, world!\0".as_ptr() as *const i8,
            "My first window\0".as_ptr() as *const i8,
            MB_OK,
        );
    }
}

//4. Using LdrGetProcedureAddress and LdrGetDllHandle to get the function pointer and call the API
use ntapi::ntldr::LdrGetDllHandle;
use ntapi::ntldr::LdrGetProcedureAddress;
use ntapi::ntrtl::RtlInitUnicodeString;
use ntapi::ntrtl::RtlUnicodeStringToAnsiString;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::ctypes::c_void as winapi_void;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::shared::ntdef::{NT_SUCCESS, STRING};
use winapi::shared::ntstatus::STATUS_SUCCESS;

fn ldr_get_dll(dll_name: &str) -> HMODULE {
    // Initialize a null pointer to a handle.
    let mut handle: *mut winapi_void = std::ptr::null_mut();
    // Initialize a UNICODE_STRING structure to hold the DLL name.
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the DLL name to a wide string.
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        // Initialize the UNICODE_STRING structure with the DLL name.
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        // Call the LdrGetDllHandle function to get a handle to the DLL.
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        // If the function call was not successful or the handle is null, return a null pointer.
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the handle to the DLL module.
    handle as HMODULE
} //ldr_get_dll

// This function retrieves the address of an exported function from a DLL module.
// The function takes a handle to a DLL module and a function name as a string, and returns a pointer to the function.
fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    // Initialize a null pointer to a function.
    let mut func: *mut winapi_void = std::ptr::null_mut();
    // Initialize a STRING structure to hold the function name.
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Initialize a UNICODE_STRING structure to hold the function name.
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    // Convert the function name to a wide string.
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        // Initialize the UNICODE_STRING structure with the function name.
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        // Convert the UNICODE_STRING to an ANSI string.
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        // Call the LdrGetProcedureAddress function to get the address of the function.
        let status = LdrGetProcedureAddress(
            dll as *mut winapi_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        // If the function call was not successful or the function pointer is null, return a null pointer.
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    // Return the pointer to the function.
    func as FARPROC
} //ldr_get_fn

fn use_ldrgetprocedureaddress() {
    // Get the handle to user32.dll
    let user32_dll = ldr_get_dll("user32.dll");
    if user32_dll.is_null() {
        println!("Failed to get handle to user32.dll");
        return;
    }

    // Get the address of the MessageBoxA function
    let message_box_a_addr = ldr_get_fn(user32_dll, "MessageBoxA");

    // Define the function type for MessageBoxA
    type MessageBoxAFn = unsafe extern "system" fn(*mut c_void, *const i8, *const i8, u32) -> i32;

    // Cast the function pointer
    let message_box_a: MessageBoxAFn = unsafe { std::mem::transmute(message_box_a_addr) };

    // Call the MessageBoxA function
    unsafe {
        message_box_a(
            null_mut(),
            "Hello, world!\0".as_ptr() as *const i8,
            "My first window\0".as_ptr() as *const i8,
            MB_OK,
        );
    }
}

use std::mem;
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW};
use winapi::um::winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW};
use windows::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;

pub fn get_ntdll_version() {
    unsafe {
        println!("Starting get_ntdll_version function");

        // Get NTDLL handle
        let ntdll = GetModuleHandleW(wide_string("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            println!("Failed to get NTDLL handle. Error: {}", GetLastError());
            return;
        }
        println!("NTDLL handle obtained successfully");
        println!("NTDLL handle: {:p}", ntdll);

        // Get NTDLL path
        let mut path = [0u16; 260];
        let len = GetModuleFileNameW(ntdll, path.as_mut_ptr(), path.len() as u32);
        if len == 0 {
            println!("Failed to get NTDLL path. Error: {}", GetLastError());
            return;
        }
        let path_os_string: OsString = OsString::from_wide(&path[..len as usize]);
        println!("NTDLL path: {:?}", path_os_string);

        // Get version info size
        let mut dummy: u32 = 0;
        let size = GetFileVersionInfoSizeW(path.as_ptr(), &mut dummy);
        if size == 0 {
            println!("Failed to get version info size. Error: {}", GetLastError());
            return;
        }
        println!("Version info size: {}", size);

        // Get version info
        let mut version_info = vec![0u8; size as usize];
        if GetFileVersionInfoW(path.as_ptr(), 0, size, version_info.as_mut_ptr() as *mut _) == 0 {
            println!("Failed to get version info. Error: {}", GetLastError());
            return;
        }
        println!("Version info obtained successfully");

        // Parse version info manually
        if version_info.len() >= mem::size_of::<VS_FIXEDFILEINFO>() {
            let file_info: &VS_FIXEDFILEINFO = mem::transmute(version_info.as_ptr().offset(0x28));
            if file_info.dwSignature == 0xFEEF04BD {
                let major = (file_info.dwFileVersionMS >> 16) & 0xFFFF;
                let minor = file_info.dwFileVersionMS & 0xFFFF;
                let build = (file_info.dwFileVersionLS >> 16) & 0xFFFF;
                let revision = file_info.dwFileVersionLS & 0xFFFF;
                println!("NTDLL version: {}.{}.{}.{}", major, minor, build, revision);
            } else {
                println!("Invalid VS_FIXEDFILEINFO signature");
            }
        } else {
            println!("Version info buffer is too small to contain VS_FIXEDFILEINFO");
        }

        // Print the first few bytes of the version_info buffer for debugging
        println!("First 32 bytes of version_info:");
        for (i, &byte) in version_info.iter().take(32).enumerate() {
            print!("{:02X} ", byte);
            if (i + 1) % 4 == 0 {
                print!(" ");
            }
            if (i + 1) % 16 == 0 {
                println!();
            }
        }
        println!();
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
// ... (implement other methods)

//implementing the methods to get the PEB and TEB using noldr
use chrono::{DateTime, Local};
use noldr::{get_dll_address, get_function_address, get_teb};
use std::time::{Duration, UNIX_EPOCH};
use winapi::shared::ntdef::LARGE_INTEGER;

fn noldr_ntapi() {
    let teb = get_teb();
    println!("TEB: {:p}", teb);

    let dll_base_address = get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    println!("DLL base address: {:p}", dll_base_address);

    let function_address = get_function_address(dll_base_address, "NtQuerySystemTime").unwrap();
    println!("Function address: {:p}", function_address);

    // Define the function type for NtQuerySystemTime
    type NtQuerySystemTimeFn = unsafe extern "system" fn(*mut LARGE_INTEGER) -> NTSTATUS;

    // Cast the function pointer
    let nt_query_system_time: NtQuerySystemTimeFn =
        unsafe { std::mem::transmute(function_address) };

    // Call the function
    unsafe {
        let mut system_time: LARGE_INTEGER = std::mem::zeroed();
        let status = nt_query_system_time(&mut system_time);
        println!("Status: {:#x}", status as u32);

        if status >= 0 {
            // Check if the call was successful
            // Convert Windows file time to Unix timestamp
            let windows_ticks = system_time.QuadPart();
            let unix_time = windows_ticks / 10_000_000 - 11_644_473_600;

            let system_time = UNIX_EPOCH + Duration::from_secs(unix_time as u64);
            let datetime: DateTime<Local> = system_time.into();

            println!(
                "Current system time: {}",
                datetime.format("%Y-%m-%d %H:%M:%S")
            );
        } else {
            println!("Failed to query system time");
        }
    }
}

//6. copy ntdll.dll to memory and locate functions in it using the ntdll exports table

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};

fn nt_in_memory() {
    unsafe {
        // Load NTDLL into memory
        let mut file =
            File::open("C:\\Windows\\System32\\ntdll.dll").expect("Failed to open NTDLL");
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).expect("Failed to read NTDLL");

        // Allocate memory for the DLL
        let base_address = VirtualAlloc(
            std::ptr::null_mut(),
            buffer.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base_address.is_null() {
            println!("Failed to allocate memory");
            return;
        }

        // Copy the DLL into the allocated memory
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), base_address as *mut u8, buffer.len());

        // Parse PE structure
        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        let nt_headers =
            (base_address as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let optional_header = &(*nt_headers).OptionalHeader;

        // Find export directory
        let export_directory_rva = optional_header.DataDirectory[0].VirtualAddress;
        let export_directory = (base_address as usize + export_directory_rva as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        // Parse export directory
        let names =
            (base_address as usize + (*export_directory).AddressOfNames as usize) as *const u32;
        let functions =
            (base_address as usize + (*export_directory).AddressOfFunctions as usize) as *const u32;
        let ordinals = (base_address as usize + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16;

        // Find the NtQuerySystemTime function
        let function_name = "NtQuerySystemTime";
        let mut function_address = None;

        for i in 0..(*export_directory).NumberOfNames {
            let name_rva = *names.offset(i as isize);
            let name = (base_address as usize + name_rva as usize) as *const i8;
            let name_str = std::ffi::CStr::from_ptr(name).to_str().unwrap_or("");

            if name_str == function_name {
                let ordinal = *ordinals.offset(i as isize) as usize;
                let function_rva = *functions.offset(ordinal as isize);
                function_address = Some(base_address as usize + function_rva as usize);
                break;
            }
        }

        if let Some(function_address) = function_address {
            println!(
                "NtQuerySystemTime found at offset: 0x{:X}",
                function_address - base_address as usize
            );

            let mut old_protect = 0;

            // Change memory protection to allow execution (but not writing)
            let protect_result = VirtualProtect(
                base_address,
                buffer.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            if protect_result == 0 {
                println!("Failed to change memory protection to PAGE_EXECUTE_READ");
                return;
            }

            // Define the function type for NtQuerySystemTime
            type NtQuerySystemTimeFn = unsafe extern "system" fn(*mut LARGE_INTEGER) -> NTSTATUS;

            // Cast the function pointer
            let nt_query_system_time: NtQuerySystemTimeFn = std::mem::transmute(function_address);

            // Call the function
            let mut system_time: LARGE_INTEGER = std::mem::zeroed();
            let status = nt_query_system_time(&mut system_time);

            if NT_SUCCESS(status) {
                // Convert Windows file time to Unix timestamp
                let windows_ticks = system_time.QuadPart();
                let unix_time = windows_ticks / 10_000_000 - 11_644_473_600;

                let system_time = UNIX_EPOCH + Duration::from_secs(unix_time as u64);
                let datetime: DateTime<Local> = system_time.into();

                println!(
                    "Current system time: {}",
                    datetime.format("%Y-%m-%d %H:%M:%S")
                );
            } else {
                println!("Failed to query system time. Status: {:#x}", status as u32);
            }
        } else {
            println!("NtQuerySystemTime function not found");
        }

        // Free the allocated memory (in a real scenario, you might want to keep it loaded)
        winapi::um::memoryapi::VirtualFree(base_address, 0, winapi::um::winnt::MEM_RELEASE);
    }
}

//now i'd like to get the teb then use the noldr function to get the DLLBase of ntdll.dll, then
//copy the loaded ntdll from memory into a new buffer, and use the exports table on the new buffer
//to find function addresses, then use the function address to call the function
//we can call RtlGetVersion as a demonstration

//we'll use noldr for the TEB walk, and then we'll use the exports table to find the address of the function

use std::ptr;

fn mem_to_mem() {
    println!("Starting mem_to_mem function");

    // Get the TEB
    let teb = get_teb();
    println!("TEB: {:p}", teb);

    if teb.is_null() {
        println!("TEB is null, aborting");
        return;
    }

    let dll_base_address = match get_dll_address("ntdll.dll".to_string(), teb) {
        Some(addr) => addr,
        None => {
            println!("Failed to get NTDLL base address");
            return;
        }
    };
    println!("DLL base address: {:p}", dll_base_address);

    // Safely read the DOS header
    let dos_header = unsafe { *(dll_base_address as *const IMAGE_DOS_HEADER) };
    println!("DOS header e_magic: {:#x}", dos_header.e_magic);
    println!("DOS header e_lfanew: {:#x}", dos_header.e_lfanew);

    // Read NT headers to get the size of the image
    let nt_headers = unsafe {
        &*((dll_base_address as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS)
    };
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    println!("Image size: {:#x}", image_size);

    // Define NtCurrentProcess() as a constant
    const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;

    // Define the function type for NtAllocateVirtualMemory
    type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
        ProcessHandle: HANDLE,
        BaseAddress: *mut *mut c_void,
        ZeroBits: ULONG_PTR,
        RegionSize: *mut SIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS;

    let function_address =
        get_function_address(dll_base_address, "NtAllocateVirtualMemory").unwrap();
    println!("NtAllocateVirtualMemory address: {:p}", function_address);

    let nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn =
        unsafe { std::mem::transmute(function_address) };

    let mut base_address: *mut c_void = std::ptr::null_mut();
    let mut region_size: SIZE_T = image_size;

    let status = unsafe {
        nt_allocate_virtual_memory(
            NT_CURRENT_PROCESS,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if !NT_SUCCESS(status) {
        println!(
            "Failed to allocate memory for the new buffer. Status: {:#x}",
            status
        );
        return;
    }

    let buffer = base_address;
    println!("Allocated buffer at: {:p}", buffer);

    // Copy NTDLL to the new buffer
    unsafe {
        ptr::copy_nonoverlapping(dll_base_address as *const u8, buffer as *mut u8, image_size);
    }
    println!("Copied {} bytes from NTDLL to new buffer", image_size);

    // Parse PE structure in the new buffer
    let nt_headers_offset = dos_header.e_lfanew as usize;
    println!("NT headers offset: {:#x}", nt_headers_offset);

    let nt_headers = (buffer as usize + nt_headers_offset) as *const IMAGE_NT_HEADERS;

    // Safely read NT headers
    let nt_headers_safe = unsafe { ptr::read(nt_headers) };
    println!("NT headers signature: {:#x}", nt_headers_safe.Signature);

    if nt_headers_safe.Signature != 0x4550 {
        // "PE\0\0"
        println!("Invalid NT headers signature");
        return;
    }

    // After verifying NT headers signature
    let optional_header = &nt_headers_safe.OptionalHeader;
    let export_directory_rva = optional_header.DataDirectory[0].VirtualAddress as usize;
    let export_directory =
        (buffer as usize + export_directory_rva) as *const IMAGE_EXPORT_DIRECTORY;

    let export_directory_safe = unsafe { ptr::read(export_directory) };

    let names = (buffer as usize + export_directory_safe.AddressOfNames as usize) as *const u32;
    let functions =
        (buffer as usize + export_directory_safe.AddressOfFunctions as usize) as *const u32;
    let ordinals =
        (buffer as usize + export_directory_safe.AddressOfNameOrdinals as usize) as *const u16;

    let function_name = "RtlGetVersion";
    let mut function_address = None;

    for i in 0..export_directory_safe.NumberOfNames {
        let name_rva = unsafe { *names.offset(i as isize) };
        let name = (buffer as usize + name_rva as usize) as *const i8;
        let name_str = unsafe { std::ffi::CStr::from_ptr(name).to_str().unwrap_or("") };

        if name_str == function_name {
            let ordinal = unsafe { *ordinals.offset(i as isize) } as usize;
            let function_rva = unsafe { *functions.offset(ordinal as isize) };
            function_address = Some(buffer as usize + function_rva as usize);
            break;
        }
    }

    if let Some(function_address) = function_address {
        println!(
            "RtlGetVersion found at offset: 0x{:X}",
            function_address - buffer as usize
        );

        let mut old_protect = 0;

        // Change memory protection to allow execution (but not writing)
        // Define the function type for NtProtectVirtualMemory
        type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
            ProcessHandle: HANDLE,
            BaseAddress: *mut PVOID,
            RegionSize: PSIZE_T,
            NewProtect: ULONG,
            OldProtect: PULONG,
        ) -> NTSTATUS;

        // Get the address of NtProtectVirtualMemory
        let nt_protect_virtual_memory_address =
            get_function_address(dll_base_address, "NtProtectVirtualMemory").unwrap();
        let nt_protect_virtual_memory: NtProtectVirtualMemoryFn =
            unsafe { std::mem::transmute(nt_protect_virtual_memory_address) };

        // Prepare parameters for NtProtectVirtualMemory
        let mut base_address = buffer as PVOID;
        let mut region_size: SIZE_T = image_size;

        // Change memory protection to allow execution (but not writing)
        let status = unsafe {
            nt_protect_virtual_memory(
                NT_CURRENT_PROCESS,
                &mut base_address,
                &mut region_size,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            )
        };

        if !NT_SUCCESS(status) {
            println!(
                "Failed to change memory protection to PAGE_EXECUTE_READ. Status: {:#x}",
                status
            );
            return;
        }

        type RtlGetVersionFn = unsafe extern "system" fn(*mut RTL_OSVERSIONINFOW) -> NTSTATUS;
        let rtl_get_version: RtlGetVersionFn = unsafe { std::mem::transmute(function_address) };

        let mut version_info: RTL_OSVERSIONINFOW = unsafe { std::mem::zeroed() };
        version_info.dwOSVersionInfoSize = std::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;

        let status = unsafe { rtl_get_version(&mut version_info) };

        if NT_SUCCESS(status) {
            println!(
                "Windows version: {}.{}.{}",
                version_info.dwMajorVersion,
                version_info.dwMinorVersion,
                version_info.dwBuildNumber
            );
        } else {
            println!("Failed to get version. Status: {:#x}", status as u32);
        }

    } else {
        println!("RtlGetVersion function not found");
    }

    // Free the allocated buffer
    type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        FreeType: ULONG,
    ) -> NTSTATUS;

    // Get the address of NtFreeVirtualMemory
    let nt_free_virtual_memory_address =
        get_function_address(dll_base_address, "NtFreeVirtualMemory").unwrap();
    let nt_free_virtual_memory: NtFreeVirtualMemoryFn =
        unsafe { std::mem::transmute(nt_free_virtual_memory_address) };

    // Prepare parameters for NtFreeVirtualMemory
    let mut base_address = buffer as PVOID;
    let mut region_size: SIZE_T = 0; // When freeing entire region, this should be 0
    let free_type = winapi::um::winnt::MEM_RELEASE;

    // Free the virtual memory
    let status = unsafe {
        nt_free_virtual_memory(
            NT_CURRENT_PROCESS,
            &mut base_address,
            &mut region_size,
            free_type,
        )
    };

    if NT_SUCCESS(status) {
        println!("Successfully freed virtual memory");
    } else {
        println!("Failed to free virtual memory. Status: {:#x}", status);
    }
}


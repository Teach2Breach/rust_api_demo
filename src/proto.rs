use std::io::{self, Write};
use std::ptr::null_mut;
//use winapi::um::winnt::WCHAR;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::um::errhandlingapi::GetLastError;
use std::fs::File;
use std::io::Read;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::ctypes::c_void;


#[no_mangle]
pub extern "system" fn Api() {
    // in this program, we will demonstrate all the various ways to make windows API calls in rust
    // we will use the litcrypt crate to encrypt strings

    // below are the methods to make windows API calls which I have already known
    // 1. using the winapi crate
    // 2. using ntapi crate
    // 3. using GetProcAddress and GetModuleHandleA to get the function pointer and call the API
    // 4. Using LdrGetProcedureAddress and LdrGetDllHandle to get the function pointer and call the API
    // 5. Using a TEB->PEB->DllBase to get the function pointer and call the NT API
    // ?. Using a TEB->PEB->DllBase, then use assembly to make a syscall to NT API (this is only working for simple syscalls, will come back to it or add an example later)
    // 6. copy ntdll.dll to memory and locate functions in it using the ntdll exports table
    // 7. Using dinvoke_rs and its several methods to make API calls

    //ok end of methods

    //now let's start implementing these methods

    // in this program, we will demonstrate all the various ways to make windows API calls in rust
    // we will use the litcrypt crate to encrypt strings

    loop {
        println!("\nChoose a method to make Windows API calls (or 0 to exit):");
        println!("1. Using the winapi crate");
        println!("2. Using ntapi crate");
        println!("3. Using GetProcAddress and GetModuleHandleA to get the function pointer and call the API");
        println!("4. Using LdrGetProcedureAddress and LdrGetDllHandle to get the function pointer and call the API");
        println!("5. Using noldr to get the function pointer and call the API");
        println!("6. copy ntdll.dll to memory and locate functions in it using the ntdll exports table");
        println!("99. Using NTDLL to get the version of the system");

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
            6 => ntdll_in_memory(),
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
use windows::Win32::Foundation::NTSTATUS;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::ctypes::c_void as winapi_void;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::{NT_SUCCESS, STRING};
use winapi::shared::ntdef::UNICODE_STRING;
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

use winapi::um::libloaderapi::{GetModuleHandleW, GetModuleFileNameW};
use winapi::um::winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW};
use windows::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;
use std::mem;

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
use noldr::{get_teb, get_dll_address, get_function_address};
use winapi::shared::ntdef::LARGE_INTEGER;
use chrono::{DateTime, Local};
use std::time::{Duration, UNIX_EPOCH};

fn noldr_ntapi() {
    let teb = get_teb();
    println!("TEB: {:p}", teb);

    let dll_base_address = get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    println!("DLL base address: {:p}", dll_base_address);

    let function_address = get_function_address(dll_base_address,  "NtQuerySystemTime").unwrap();
    println!("Function address: {:p}", function_address);

    // Define the function type for NtQuerySystemTime
    type NtQuerySystemTimeFn = unsafe extern "system" fn(*mut LARGE_INTEGER) -> NTSTATUS;

    // Cast the function pointer
    let nt_query_system_time: NtQuerySystemTimeFn = unsafe { std::mem::transmute(function_address) };

    // Call the function
    unsafe {
        let mut system_time: LARGE_INTEGER = std::mem::zeroed();
        let status = nt_query_system_time(&mut system_time);
        println!("Status: {:#x}", status.0 as u32);

        if status.0 >= 0 { // Check if the call was successful
            // Convert Windows file time to Unix timestamp
            let windows_ticks = system_time.QuadPart();
            let unix_time = windows_ticks / 10_000_000 - 11_644_473_600;

            let system_time = UNIX_EPOCH + Duration::from_secs(unix_time as u64);
            let datetime: DateTime<Local> = system_time.into();

            println!("Current system time: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
        } else {
            println!("Failed to query system time");
        }
    }
}

//6. copy ntdll.dll to memory and locate functions in it using the ntdll exports table

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

fn ntdll_in_memory() {
    unsafe {
        // Load NTDLL into memory
        let mut file = File::open("C:\\Windows\\System32\\ntdll.dll").expect("Failed to open NTDLL");
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
        let nt_headers = (base_address as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let optional_header = &(*nt_headers).OptionalHeader;

        // Find export directory
        let export_directory_rva = optional_header.DataDirectory[0].VirtualAddress;
        let export_directory = (base_address as usize + export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        // Parse export directory
        let names = (base_address as usize + (*export_directory).AddressOfNames as usize) as *const u32;
        let functions = (base_address as usize + (*export_directory).AddressOfFunctions as usize) as *const u32;
        let ordinals = (base_address as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;

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
            println!("NtQuerySystemTime found at offset: 0x{:X}", function_address - base_address as usize);

            // Change memory protection to allow execution
            let mut old_protect = 0;
            VirtualProtect(
                base_address,
                buffer.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            // Define the function type for NtQuerySystemTime
            type NtQuerySystemTimeFn = unsafe extern "system" fn(*mut LARGE_INTEGER) -> NTSTATUS;
            
            // Cast the function pointer
            let nt_query_system_time: NtQuerySystemTimeFn = std::mem::transmute(function_address);
            
            // Call the function
            let mut system_time: LARGE_INTEGER = std::mem::zeroed();
            let status = nt_query_system_time(&mut system_time);
            
            if NT_SUCCESS(status.0) {
                // Convert Windows file time to Unix timestamp
                let windows_ticks = system_time.QuadPart();
                let unix_time = windows_ticks / 10_000_000 - 11_644_473_600;

                let system_time = UNIX_EPOCH + Duration::from_secs(unix_time as u64);
                let datetime: DateTime<Local> = system_time.into();

                println!("Current system time: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
            } else {
                println!("Failed to query system time. Status: {:#x}", status.0 as u32);
            }
        } else {
            println!("NtQuerySystemTime function not found");
        }

        // Free the allocated memory (in a real scenario, you might want to keep it loaded)
        winapi::um::memoryapi::VirtualFree(base_address, 0, winapi::um::winnt::MEM_RELEASE);
    }
}
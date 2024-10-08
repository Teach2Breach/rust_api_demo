use std::io::{self, Write};
use std::ptr::null_mut;

#[no_mangle]
pub extern "system" fn Api() {
    // in this program, we will demonstrate all the various ways to make windows API calls in rust
    // we will use the litcrypt crate to encrypt strings

    // below are the methods to make windows API calls which I have already known
    // 1. using the winapi crate
    // 2. using ntapi crate
    // 3. using GetProcAddress and GetModuleHandleA to get the function pointer and call the API
    // 4. Using LdrGetProcedureAddress and LdrGetDllHandle to get the function pointer and call the API
    // 5. Using a TEB->PEB->LDR_DATA_TABLE_ENTRY->DllBase to get the function pointer and call the API
    // 6. Using a TEB->PEB->LDR_DATA_TABLE_ENTRY->DllBase, then use assembly to make a syscall to NT API
    // 7. Using dinvoke_rs and its several methods to make API calls

    //ok end of methods

    //now let's start implementing these methods

    // in this program, we will demonstrate all the various ways to make windows API calls in rust
    // we will use the litcrypt crate to encrypt strings

    loop {
        println!("\nChoose a method to make Windows API calls (or 0 to exit):");
        println!("1. Using the winapi crate");
        println!("2. Using ntapi crate");
        // ... (print other options)

        print!("Enter the number of the method you want to use: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice: u32 = input.trim().parse().unwrap_or(0);

        match choice {
            0 => break,
            1 => use_winapi(),
            2 => use_ntapi(),
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

// ... (implement other methods)

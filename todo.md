- obfuscating the new copy of NTDLL could help. You could implement a simple XOR encryption on the copied memory, decrypting only the parts you need when you need them.
- Just-in-time decryption:
- Instead of decrypting the entire NTDLL copy, decrypt only the functions you need, when you need them, and re-encrypt them immediately after use.
- Memory shuffling:
Periodically move the copied NTDLL to a new memory location and update your references accordingly.

xor encryption
```Rust
// After copying NTDLL to the new buffer
let xor_key = 0xAA; // Choose a key
for i in 0..image_size {
    unsafe {
        let byte_ptr = (buffer as *mut u8).add(i);
        *byte_ptr ^= xor_key;
    }
}

// When you need to use a function, decrypt it first
// (You'd need to know the function's offset and size)
fn decrypt_function(buffer: *mut u8, offset: usize, size: usize, key: u8) {
    for i in offset..(offset + size) {
        unsafe {
            let byte_ptr = buffer.add(i);
            *byte_ptr ^= key;
        }
    }
}
```

decryption routines
```Rust
fn find_and_decrypt_function(buffer: *mut u8, image_size: usize, function_name: &str, key: u8) -> Option<*mut u8> {
    // First, decrypt the DOS header to find the e_lfanew field
    decrypt_region(buffer, 0, std::mem::size_of::<IMAGE_DOS_HEADER>(), key);
    let dos_header = unsafe { &*(buffer as *const IMAGE_DOS_HEADER) };
    
    // Decrypt the NT headers
    let nt_headers_offset = dos_header.e_lfanew as usize;
    decrypt_region(buffer, nt_headers_offset, std::mem::size_of::<IMAGE_NT_HEADERS>(), key);
    let nt_headers = unsafe { &*(buffer.add(nt_headers_offset) as *const IMAGE_NT_HEADERS) };
    
    // Find and decrypt the export directory
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_dir_size = nt_headers.OptionalHeader.DataDirectory[0].Size as usize;
    decrypt_region(buffer, export_dir_rva, export_dir_size, key);
    
    // Parse the export directory to find the function
    let export_dir = unsafe { &*(buffer.add(export_dir_rva) as *const IMAGE_EXPORT_DIRECTORY) };
    let names = buffer.add(export_dir.AddressOfNames as usize) as *const u32;
    let functions = buffer.add(export_dir.AddressOfFunctions as usize) as *const u32;
    let ordinals = buffer.add(export_dir.AddressOfNameOrdinals as usize) as *const u16;
    
    for i in 0..export_dir.NumberOfNames {
        let name_rva = unsafe { *names.add(i as usize) } as usize;
        decrypt_region(buffer, name_rva, function_name.len() + 1, key);
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.add(name_rva) as *const i8) };
        
        if name.to_str().unwrap_or("") == function_name {
            let ordinal = unsafe { *ordinals.add(i as usize) } as usize;
            let function_rva = unsafe { *functions.add(ordinal) } as usize;
            
            // Decrypt a reasonable chunk of memory for the function (e.g., 1024 bytes)
            decrypt_region(buffer, function_rva, 1024, key);
            
            return Some(unsafe { buffer.add(function_rva) });
        }
    }
    
    None
}

fn decrypt_region(buffer: *mut u8, offset: usize, size: usize, key: u8) {
    for i in offset..(offset + size) {
        unsafe {
            let byte_ptr = buffer.add(i);
            *byte_ptr ^= key;
        }
    }
}
```

shuffle memory
```Rust
fn shuffle_memory(current_buffer: *mut c_void, size: usize) -> *mut c_void {
    let mut new_buffer: *mut c_void = std::ptr::null_mut();
    let mut region_size: SIZE_T = size;

    unsafe {
        nt_allocate_virtual_memory(
            NT_CURRENT_PROCESS,
            &mut new_buffer,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        ptr::copy_nonoverlapping(current_buffer as *const u8, new_buffer as *mut u8, size);

        // Free the old buffer
        // ... (code to free current_buffer)
    }

    new_buffer
}
```
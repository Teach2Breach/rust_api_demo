this stuff for improving the method used in step 7 fn mem_to_mem
- obfuscating the new copy of NTDLL could help. You could implement a simple XOR encryption on the copied memory, decrypting only the parts you need when you need them.
- Just-in-time decryption:
- Instead of decrypting the entire NTDLL copy, decrypt only the functions you need, when you need them, and re-encrypt them immediately after use.
- Memory shuffling:
Periodically move the copied NTDLL to a new memory location and update your references accordingly.

xor encryption wont be safe. implement the below option instead:
"You can perform AES encryption using Windows APIs, but it requires a combination of multiple API calls to encrypt and decrypt data. An excellent solution for this problem is hinted at in Mimikatz. The author implements SystemFunction032: a system function that can be resolved from advapi32.dll to perform RC4 encryption and decryption. This API call accepts two arguments that contain the target memory and a key, allowing us to dynamically generate a key and encrypt data without executing code in private commit memory. Technically, SystemFunction032 is for encryption, and SystemFunction033 is for decryption. The RC4 cipher is bidirectional, though, so you can use either API for encryption or decryption."

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

this is for a new method using https://github.com/Teach2Breach/rust_syscalls
I forked it. I need to test it and then make modifications to it for opsec reasons. Then implement it.

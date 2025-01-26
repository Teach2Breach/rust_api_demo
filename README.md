#### Windows API Calls in Rust

This project demonstrates various methods to make Windows API calls in Rust. Each method is implemented and explained in detail.

##### Methods Implemented

1. Using the winapi crate
2. Using ntapi crate 
3. Using GetProcAddress and GetModuleHandleA 
4. Using LdrGetProcedureAddress and LdrGetDllHandle 
5. Using TEB->PEB->LDR_DATA_TABLE_ENTRY->DllBase 
6. Copy ntdll from on disk to memory buffer and locate functions by searching the buffer
7. Copy ntdll from memory buffer to a new buffer in memory and locate functions by searching the buffer

##### Method 1: Using the winapi crate

This method utilizes the `winapi` crate to make Windows API calls directly in Rust.

###### Setup

1. Add the `winapi` crate to your `Cargo.toml`:

```toml
[dependencies]
winapi = { version = "0.3", features = ["winuser"] }
```

2. Import the necessary functions from the `winapi` crate in your Rust file:

```rust
use winapi::um::winuser::MessageBoxA;
```

###### Usage

Call the `MessageBoxA` function to display a message box:

```rust
unsafe {
    MessageBoxA(
        null_mut(),
        "Hello, world!\0".as_ptr() as *const i8,
        "My first window\0".as_ptr() as *const i8,
        MB_OK,
    );
}


This code creates a message box with the title "My first window" and the message "Hello, world!".

### Notes

- The `unsafe` block is necessary because we're calling external C functions.
- Strings need to be null-terminated and converted to the appropriate pointer type.
- The `MB_OK` flag specifies that the message box should have an OK button.

## Next Steps

Document the remaining methods for making Windows API calls in Rust.



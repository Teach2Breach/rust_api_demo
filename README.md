#### Windows API Calls in Rust

This project demonstrates various methods to make Windows API calls in Rust. 

##### Methods Implemented

1. Using the winapi crate
2. Using ntapi crate 
3. Using GetProcAddress and GetModuleHandleA 
4. Using LdrGetProcedureAddress and LdrGetDllHandle 
5. Using TEB->PEB->LDR_DATA_TABLE_ENTRY->DllBase 
6. Copy ntdll from on disk to memory buffer and locate functions by searching the buffer
7. Copy ntdll from memory buffer to a new buffer in memory and locate functions by searching the buffer



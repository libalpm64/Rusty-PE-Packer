use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use sysinfo::System;

pub fn is_debugger_present() {
    unsafe {
        if IsDebuggerPresent().into() {
            panic!("＼（〇_ｏ）／");
        }
    }
}

pub fn process_list() {
    let list = vec![
        "ollydbg.exe",
        "windbg.exe",
        "x64dbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "procmon.exe",
        "processhacker.exe",
        "procexp.exe",
        "procdump.exe",
        "VsDebugConsole.exe",
        "msvsmon.exe",
        "x32dbg.exe"
    ];

    let mut system = System::new_all();
    system.refresh_all();

    for (_pid, process) in system.processes() {
        for name in &list {
            if process.name() == *name {
                panic!(":( For Real?");
            }
        }
    }
} 

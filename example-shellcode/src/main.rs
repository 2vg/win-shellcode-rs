#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]
#![feature(asm)]

mod binding;
use binding::*;

use core::mem::transmute;
use utf16_literal::utf16;

pub type PLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
pub type PGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> LPVOID;
pub type PMessageBoxW = unsafe extern "system" fn(h: PVOID, text: LPCWSTR, cation: LPCWSTR, t: u32) -> u32;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub unsafe extern "C" fn main() {
    let kernel32 = get_module_by_name(utf16!("KERNEL32.DLL\x00").as_ptr());
    let LoadLibraryA: PLoadLibraryA = transmute(get_func_by_name(kernel32, "LoadLibraryA\x00".as_ptr() as _));
    let GetProcAddress: PGetProcAddress = transmute(get_func_by_name(kernel32, "GetProcAddress\x00".as_ptr() as _));

    let u32_dll = LoadLibraryA("user32.dll\x00".as_ptr() as _);
    let MessageBoxW: PMessageBoxW = transmute(GetProcAddress(u32_dll, "MessageBoxW\x00".as_ptr() as _));

    MessageBoxW(
        NULL,
        utf16!("Hello, I'm 烏魯\0").as_ptr(),
        utf16!("From shellcode\0").as_ptr(),
        0x00,
    );
}

unsafe fn get_module_by_name(module_name: *const u16) -> PVOID {
    let mut ppeb = NULL as *mut PEB;
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) ppeb,
    );

    let p_peb_ldr_data = (*ppeb).Ldr;
    let mut module_list =
        (*p_peb_ldr_data).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while (*module_list).DllBase != NULL {
        let dll_name = (*module_list).BaseDllName.Buffer;

        if compare_raw_str(module_name, dll_name) {
            return (*module_list).DllBase;
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    NULL
}

unsafe fn get_func_by_name(module: PVOID, func_name: *const u8) -> PVOID {
    let nt_header = (module as u64
        + (*(module as *mut IMAGE_DOS_HEADER)).e_lfanew as u64)
        as *mut IMAGE_NT_HEADERS64;
    let export_dir_rva = (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as u64;

    if export_dir_rva == 0x0 {
        return NULL;
    };

    let export_dir = (module as u64 + export_dir_rva) as *mut IMAGE_EXPORT_DIRECTORY;

    let number_of_names = (*export_dir).NumberOfNames;
    let addr_of_funcs = (*export_dir).AddressOfFunctions;
    let addr_of_names = (*export_dir).AddressOfNames;
    let addr_of_ords = (*export_dir).AddressOfNameOrdinals;
    for i in 0..number_of_names {
        let name_rva_p: *const DWORD =
            (module as *const u8).offset((addr_of_names + i * 4) as isize) as *const _;
        let name_index_p: *const WORD =
            (module as *const u8).offset((addr_of_ords + i * 2) as isize) as *const _;
        let name_index = name_index_p.as_ref().unwrap();
        let mut off: u32 = (4 * name_index) as u32;
        off = off + addr_of_funcs;
        let func_rva: *const DWORD = (module as *const u8).offset(off as _) as *const _;

        let name_rva = name_rva_p.as_ref().unwrap();
        let curr_name = (module as *const u8).offset(*name_rva as isize);

        if *curr_name == 0 {
            continue;
        }
        if compare_raw_str(func_name, curr_name) {
            let res = (module as *const u8).offset(*func_rva as isize);
            return res as _;
        }
    }

    return NULL;
}

use num_traits::Num;
pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num,
{
    unsafe {
        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);

        if s_len != u_len {
            return false;
        }
        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
        return true;
    }
}

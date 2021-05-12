use anyhow::{Context, Result};
use goblin::pe::PE;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;

const BITNESS: u32 = 64;

fn main() -> Result<()> {
    let src_path = "shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.exe";
    let mut buffer = get_binary_from_file(src_path)?;
    let pe = PE::parse(&mut buffer)?;
    let standard_fileds = pe.header.optional_header.unwrap().standard_fields;
    let entry_offset = standard_fileds.address_of_entry_point - standard_fileds.base_of_code;

    for section in pe.sections {
        let name = String::from_utf8(section.name.to_vec())?;
        if !name.starts_with(".text") {
            continue;
        }
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let dst_path = ".\\shellcode.bin";
        let shellcode = File::create(dst_path)?;
        let mut bootstrap: Vec<u8> = Vec::new();

        /*
         *     ;bootstrap shellcode
         *     call    0x5
         *     pop     rcx
         *     push    rsi
         *     mov     rsi,rsp
         *     and     rsp,0xfffffffffffffff0
         *     sub     rsp,0x20
         *     call    0x5
         *     mov     rsp,rsi
         *     pop     rsi
         *     ret
         */

        bootstrap.extend_from_slice(b"\xe8\x00\x00\x00\x00");
        bootstrap.push(b'\x59');
        bootstrap.push(b'\x56');
        bootstrap.extend_from_slice(b"\x48\x89\xe6");
        bootstrap.extend_from_slice(b"\x48\x83\xe4\xf0");
        bootstrap.extend_from_slice(b"\x48\x83\xec\x20");
        bootstrap.push(b'\xe8');
        bootstrap.push(5 as u8);
        bootstrap.extend_from_slice(b"\x00\x00\x00");
        bootstrap.extend_from_slice(b"\x48\x89\xf4");
        bootstrap.push(b'\x5e');
        bootstrap.push(b'\xc3');

        let mut buf_writer = BufWriter::new(shellcode);

        // write bootstrap first
        for b in bootstrap {
            buf_writer.write(&[b])?;
        }

        // write jmp to entry code
        buf_writer.write(&[0xe9])?;

        // in most cases, i don't think the entry point address will be greater than u32 ...
        // therefore, it is cast to u32 here, but if it becomes a 64-bit address, it needs to be fixed.
        for byte in &(entry_offset as u32).to_le_bytes() {
            buf_writer.write(&[*byte])?;
        }

        // write main code
        for i in start..start + size {
            buf_writer.write(&[buffer[i]])?;
        }

        buf_writer.flush()?;

        println!("== .text section start ==");
        let binary = &buffer[start..start + size];
        maidism::disassemble(binary, 0x0, 0x0, 6, BITNESS, true)?;

        println!("== main entry code ==");
        let binary = &buffer[entry_offset as usize..entry_offset as usize + size];
        maidism::disassemble(binary, 0x0, 0x0, 6, BITNESS, true)?;

        println!("== shellcode ==");
        let binary = get_binary_from_file(dst_path)?;
        maidism::disassemble(&binary, 0x0, 0x0, 16, BITNESS, true)?;

        println!("done! shellcode saved in {}", dst_path);
    }
    Ok(())
}

fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name)
        .with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

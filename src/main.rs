use winapi::shared::{
    minwindef::LPVOID,
    minwindef::DWORD
};
use std::mem;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use std::ffi::CString;
use std::ptr::{null, null_mut};
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::winuser::MessageBoxA;
use std::io;
use sysinfo::{ProcessExt, System, SystemExt};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::libloaderapi::{
    GetModuleHandleA,
};

pub struct ProcessInfo{
    name:String,
    pid:usize,
    handle:HANDLE 
}

impl ProcessInfo {

    fn get_process_by_name(pName:&str) -> Vec<usize> {

            let sys = System::new_all();
            let mut process_vec = Vec::new();
        
            for (pid, process) in sys.processes() {
                if process.name() == pName {
                    process_vec.push(pid.clone());
                }
            }
        
            process_vec
        
    }
    
    pub fn new(process_name:&str) -> ProcessInfo{

        let pid  = *ProcessInfo::get_process_by_name(&process_name).get(0).expect("ERROR!");

        println!("pid = {}", pid);

        let handle:HANDLE = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, 0, pid as u32)
        };

        ProcessInfo{
            name:process_name.to_string(),
            pid:pid,
            handle:handle

        }

    }

    pub fn inject_dll(&self, dllPath:String) -> bool{

        let addr = unsafe{
            GetProcAddress(GetModuleHandleA("kernel32.dll\0".as_ptr() as _), "LoadLibraryA\0".as_ptr() as _)
        };

        let dll_path_str = CString::new(dllPath).unwrap();
        let dll_path_len = dll_path_str.as_bytes_with_nul().len() + 1;

        let alloc_mem = unsafe {
            VirtualAllocEx(self.handle, null_mut(), dll_path_len, MEM_COMMIT, PAGE_READWRITE)
        };

        unsafe{
            WriteProcessMemory(self.handle, alloc_mem, dll_path_str.as_ptr() as _ , dll_path_len, null_mut());
            type thread_func = unsafe extern "system" fn(LPVOID)->DWORD;
            let func:thread_func = mem::transmute(addr);
            CreateRemoteThread(self.handle, null_mut(), 0, Some(func), alloc_mem, 0, null_mut());
        }

        return false;
    }

}



fn main() {

    println!("目标进程名:");

    let mut target_process_name : String = String::new();
    io::stdin().read_line(&mut target_process_name).unwrap();

    let processInfo = ProcessInfo::new(&target_process_name.trim());

    println!("目标DLL路径");
    let mut target_dll_path = String::new();
    io::stdin().read_line(&mut target_dll_path).unwrap();

    processInfo.inject_dll(target_dll_path.trim().to_string());

    println!("操作完成");
    io::stdin().read_line(&mut target_process_name).unwrap();

}

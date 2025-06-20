use std::env;
use std::process;
use std::time::Duration;
use pcap::Device;
use std::sync::{Arc, Mutex};
use web::server::{AppState, start_server};

mod interface;
mod parser;
mod capture;
mod display;
mod web;

use interface::WifiInterface;
use parser::{capture_and_parse, get_access_points};
use display::{display_results, log_to_file};
use std::collections::HashMap;
use parser::FrameType;
use parser::ManagementSubtype;

#[cfg(unix)]
extern crate libc;

fn check_root_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe {
            libc::geteuid() == 0
        }
    }
    
    #[cfg(not(unix))]
    {
        false
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("Starting Wi-Fi Monitor...");

    if !check_root_privileges() {
        eprintln!("Error: This application requires root privileges.");
        eprintln!("Please run with sudo or as root.");
        process::exit(1);
    }
    
    let args: Vec<String> = env::args().collect();
    let interface_name = if args.len() > 1 {
        args[1].clone()
    } else {
        match find_wifi_interface() {
            Some(interface) => {
                println!("Auto-detected Wi-Fi interface: {}", interface);
                interface
            },
            None => {
                eprintln!("Error: No Wi-Fi interface found. Please specify one.");
                eprintln!("Usage: {} <interface>", args[0]);
                process::exit(1);
            }
        }
    };

    let interface = WifiInterface::new(&interface_name);
    println!("Using interface: {}", interface.get_interface_name());

    println!("Setting interface to monitor mode...");
    if let Err(e) = interface.set_monitor_mode() {
        eprintln!("Failed to set monitor mode: {}", e);
        return Err(e);
    }
    println!("Interface is now in monitor mode");

    let interface_clone = interface_name.clone();
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        
        let cleanup_interface = WifiInterface::new(&interface_clone);
        if let Err(e) = cleanup_interface.set_managed_mode() {
            eprintln!("Warning: Failed to restore managed mode: {}", e);
        } else {
            println!("Interface restored to managed mode");
        }
        
        process::exit(0);
    }).expect("Error setting Ctrl+C handler");

    let hopping_interface = interface_name.clone();
    std::thread::spawn(move || {
        channel_hopping(&hopping_interface);
    });

    // Initialize and start the web server in a separate thread
    /*
    let state = AppState {
        captured_data: Arc::new(Mutex::new(Vec::new())),
    };

    let web_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = start_server(web_state).await {
            eprintln!("Web server error: {}", e);
        }
    });

    println!("Web server started at http://127.0.0.1:8080");
    */
    println!("Starting packet capture (press Ctrl+C to stop)...");
    loop {
        match capture_and_parse(&interface_name, 5000, None) { 
            Ok(frames) => {
                println!("Captured {} frames", frames.len());
                
                for frame in &frames {
                    if let Some(ssid) = &frame.ssid {
                        display_results(&frame.mac_src, ssid, frame.rssi.unwrap_or(0) as i32);
                        
                        if let Err(e) = log_to_file(&frame.mac_src, ssid, frame.rssi.unwrap_or(0) as i32) {
                            eprintln!("Error logging to file: {}", e);
                        }
                    }
                }
                /*
                if let Ok(mut data) = state.captured_data.lock() {
                    for frame in &frames {
                        if let Some(ssid) = &frame.ssid {
                            data.push(format!("MAC: {}, SSID: {}, RSSI: {}", 
                                        frame.mac_src, ssid, frame.rssi.unwrap_or(0)));
                        }
                    }
                }
                */
                let access_points = get_access_points(&frames);
                if !access_points.is_empty() {
                    println!("\n--- Detected Access Points ---");
                    println!("{:<17} {:<32} {:<6} {:<8} {:<10}", "BSSID", "SSID", "RSSI", "Channel", "Security");
                    for ap in access_points.values() {
                        let display_ssid = if ap.ssid == "<hidden>" && mac_to_ssid.contains_key(&ap.bssid) {
                            format!("{} (uncovered)", mac_to_ssid.get(&ap.bssid).unwrap())
                        } else {
                            ap.ssid.clone()
                        };
                        
                        println!("{:<17} {:<32} {:<6} {:<8} {:<10}",
                                ap.bssid,
                                display_ssid,
                                ap.rssi.map_or("?".to_string(), |r| r.to_string()),
                                ap.channel.map_or("?".to_string(), |c| c.to_string()),
                                ap.security.as_ref().map_or("Unknown".to_string(), |s| format!("{:?}", s)));
                    }
                    println!();
                }

                for frame in &frames {
                    if let Some(payload) = &frame.payload {
                        if payload.len() > 0 {
                            println!("DATA PACKET: {} -> {}", frame.mac_src, frame.mac_dst);
                            println!("  Length: {} bytes", frame.frame_length);
                            println!("  Sequence: {}", frame.sequence_number.unwrap_or(0));
                            
                            println!("  Payload (first 48 bytes):");
                            print_hex_dump(&payload[..std::cmp::min(48, payload.len())]);
                            println!();
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Error capturing frames: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

// Interface finder thingy
fn find_wifi_interface() -> Option<String> {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(_) => return None,
    };
    
    for device in &devices {
        let name = &device.name;
        if name.starts_with("wlan") && name != "wlan0" {
            return Some(name.clone());
        }
    }
    
    for device in devices {
        let name = device.name;
        if name.starts_with("wlan") || name.contains("wl") {
            return Some(name);
        }
    }
    
    None
}

fn channel_hopping(interface: &str) {
    let wifi = WifiInterface::new(interface);
    let channels = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13];
    
    loop {
        for &channel in &channels {
            if let Err(e) = wifi.set_channel(channel) {
                eprintln!("Failed to set channel {}: {}", channel, e);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn print_hex_dump(data: &[u8]) {
    for chunk in data.chunks(16) {
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        
        print!(" | ");
        
        for &byte in chunk {
            if byte >= 32 && byte <= 126 {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
    
    println!("\n  Text extraction:");
    extract_text_from_payload(data);
}

fn extract_text_from_payload(data: &[u8]) {
    let mut text_buffer = Vec::new();
    let mut in_text = false;
    let mut text_pos = 0;
    
    for (i, &byte) in data.iter().enumerate() {
        if byte >= 32 && byte <= 126 {
            if !in_text {
                in_text = true;
                text_pos = i;
            }
            text_buffer.push(byte);
        } else if in_text {
            if text_buffer.len() >= 4 {  
                let text = String::from_utf8_lossy(&text_buffer);
                println!("    Position {}-{}: \"{}\"", text_pos, i-1, text);
            }
            text_buffer.clear();
            in_text = false;
        }
    }
    
    if in_text && text_buffer.len() >= 4 {
        let text = String::from_utf8_lossy(&text_buffer);
        println!("    Position {}-{}: \"{}\"", text_pos, data.len()-1, text);
    }
    
    if !in_text && text_buffer.is_empty() {
        println!("    No readable text found in payload");
    }
}

fn discover_networks(interface_name: &str) -> Result<HashMap<String, String>, String> {
    println!("Starting network discovery phase (15 seconds)...");
    
    let frames = capture_and_parse(interface_name, 15000, None)?;
    
    let mut mac_to_ssid = HashMap::new();
    let mut ap_count = 0;
    
    for frame in &frames {
        if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
            if !mac_to_ssid.contains_key(bssid) && ssid != "<hidden>" {
                mac_to_ssid.insert(bssid.clone(), ssid.clone());
                ap_count += 1;
            }
        }
        
        if let FrameType::Data(_) = &frame.frame_type {
            if let Some(bssid) = &frame.bssid {
                if !mac_to_ssid.contains_key(bssid) {
                    mac_to_ssid.insert(bssid.clone(), format!("Unknown AP ({})", bssid));
                }
            }
        }
    }
    
    println!("Discovery complete. Found {} networks with identifiable SSIDs", ap_count);
    
    Ok(mac_to_ssid)
}


println!("Running initial network discovery...");
let mac_to_ssid = match discover_networks(&interface_name) {
    Ok(mapping) => mapping,
    Err(e) => {
        eprintln!("Warning: Network discovery failed: {}. Continuing without it.", e);
        HashMap::new()
    }
};

let access_points = get_access_points(&frames);
if !access_points.is_empty() {
    println!("\n--- Detected Access Points ---");
    println!("{:<17} {:<32} {:<6} {:<8} {:<10}", "BSSID", "SSID", "RSSI", "Channel", "Security");
    for ap in access_points.values() {
        let display_ssid = if ap.ssid == "<hidden>" && mac_to_ssid.contains_key(&ap.bssid) {
            format!("{} (uncovered)", mac_to_ssid.get(&ap.bssid).unwrap())
        } else {
            ap.ssid.clone()
        };
        
        println!("{:<17} {:<32} {:<6} {:<8} {:<10}",
                ap.bssid,
                display_ssid,
                ap.rssi.map_or("?".to_string(), |r| r.to_string()),
                ap.channel.map_or("?".to_string(), |c| c.to_string()),
                ap.security.as_ref().map_or("Unknown".to_string(), |s| format!("{:?}", s)));
    }
    println!();
}
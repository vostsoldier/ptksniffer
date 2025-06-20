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

    println!("Starting packet capture (press Ctrl+C to stop)...");
    loop {
        match capture_and_parse(&interface_name, 5000, Some("type mgt")) {
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
                
                if let Ok(mut data) = state.captured_data.lock() {
                    for frame in &frames {
                        if let Some(ssid) = &frame.ssid {
                            data.push(format!("MAC: {}, SSID: {}, RSSI: {}", 
                                        frame.mac_src, ssid, frame.rssi.unwrap_or(0)));
                        }
                    }
                }
                
                let access_points = get_access_points(&frames);
                if !access_points.is_empty() {
                    println!("\n--- Detected Access Points ---");
                    println!("{:<17} {:<32} {:<6} {:<8}", "BSSID", "SSID", "RSSI", "Channel");
                    for ap in access_points.values() {
                        println!("{:<17} {:<32} {:<6} {:<8}",
                                 ap.bssid,
                                 ap.ssid,
                                 ap.rssi.map_or("?".to_string(), |r| r.to_string()),
                                 ap.channel.map_or("?".to_string(), |c| c.to_string()));
                    }
                    println!();
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
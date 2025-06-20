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

    println!("Running network discovery...");
    println!("Phase 1: Basic discovery");
    let mut mac_to_ssid = match discover_networks(&interface_name) {
        Ok(mapping) => mapping,
        Err(e) => {
            eprintln!("Warning: Network discovery failed: {}. Continuing without it.", e);
            HashMap::new()
        }
    };

    println!("Phase 2: Aggressive hidden SSID discovery");
    match aggressive_ssid_discovery(&interface_name) {
        Ok(hidden_mapping) => {
\            for (mac, ssid) in hidden_mapping {
                mac_to_ssid.insert(mac, ssid);
            }
        },
        Err(e) => {
            eprintln!("Warning: Aggressive discovery failed: {}. Using basic results.", e);
        }
    };

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
\                            let ap_name = if let Some(bssid) = &frame.bssid {
                                if mac_to_ssid.contains_key(bssid) {
                                    format!("{} ({})", bssid, mac_to_ssid.get(bssid).unwrap())
                                } else {
                                    bssid.clone()
                                }
                            } else {
                                "Unknown AP".to_string()
                            };
                            
                            println!("\nDATA PACKET: {} → {} via {}", 
                                    frame.mac_src, frame.mac_dst, ap_name);
                            println!("  Length: {} bytes", frame.frame_length);
                            println!("  Sequence: {}", frame.sequence_number.unwrap_or(0));
                            
                            println!("  Analysis:");
                            let insights = analyze_data_packet(frame);
                            for insight in insights {
                                println!("    • {}", insight);
                            }
                            
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

fn analyze_data_packet(frame: &parser::ParsedFrame) -> Vec<String> {
    let mut insights = Vec::new();
    
    if let Some(payload) = &frame.payload {
        if payload.len() < 8 {
            return vec!["Packet too short for analysis".to_string()];
        }
        
        if payload.len() >= 8 && payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03 {
            let protocol_type = ((payload[6] as u16) << 8) | (payload[7] as u16);
            
            match protocol_type {
                0x0800 => {
                    insights.push("IPv4 packet".to_string());
                    if payload.len() >= 20 + 8 {
                        let ip_header_len = (payload[8] & 0x0F) * 4;
                        let src_ip = format!("{}.{}.{}.{}", 
                                     payload[12+8], payload[13+8], payload[14+8], payload[15+8]);
                        let dst_ip = format!("{}.{}.{}.{}", 
                                     payload[16+8], payload[17+8], payload[18+8], payload[19+8]);
                        insights.push(format!("Source IP: {}", src_ip));
                        insights.push(format!("Destination IP: {}", dst_ip));
                        
                        if payload.len() >= 8 + ip_header_len + 4 {
                            let protocol = payload[9+8];
                            match protocol {
                                6 => {
                                    insights.push("TCP packet".to_string());
                                    if payload.len() >= 8 + ip_header_len + 4 {
                                        let offset = 8 + ip_header_len as usize;
                                        let src_port = ((payload[offset] as u16) << 8) | (payload[offset+1] as u16);
                                        let dst_port = ((payload[offset+2] as u16) << 8) | (payload[offset+3] as u16);
                                        insights.push(format!("TCP Ports: {} → {}", src_port, dst_port));
                                        
                                        let service = match dst_port {
                                            80 => "HTTP",
                                            443 => "HTTPS",
                                            22 => "SSH",
                                            21 => "FTP",
                                            25 => "SMTP",
                                            110 => "POP3",
                                            143 => "IMAP",
                                            53 => "DNS",
                                            _ => "Unknown"
                                        };
                                        if service != "Unknown" {
                                            insights.push(format!("Service: {}", service));
                                        }
                                    }
                                },
                                17 => {
                                    insights.push("UDP packet".to_string());
                                    if payload.len() >= 8 + ip_header_len + 4 {
                                        let offset = 8 + ip_header_len as usize;
                                        let src_port = ((payload[offset] as u16) << 8) | (payload[offset+1] as u16);
                                        let dst_port = ((payload[offset+2] as u16) << 8) | (payload[offset+3] as u16);
                                        insights.push(format!("UDP Ports: {} → {}", src_port, dst_port));
                                        
                                        if src_port == 53 || dst_port == 53 {
                                            insights.push("Service: DNS".to_string());
                                        }
                                    }
                                },
                                1 => {
                                    insights.push("ICMP packet".to_string());
                                },
                                _ => {
                                    insights.push(format!("IP Protocol: {}", protocol));
                                }
                            }
                        }
                    }
                },
                0x0806 => {
                    insights.push("ARP packet".to_string());
                    if payload.len() >= 28 + 8 {
                        let operation = ((payload[6+8] as u16) << 8) | (payload[7+8] as u16);
                        if operation == 1 {
                            insights.push("ARP Request".to_string());
                        } else if operation == 2 {
                            insights.push("ARP Reply".to_string());
                        }
                    }
                },
                0x86DD => {
                    insights.push("IPv6 packet".to_string());
                    if payload.len() >= 40 + 8 {
                        let src_ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:...",
                                      payload[8+8], payload[9+8], payload[10+8], payload[11+8],
                                      payload[12+8], payload[13+8], payload[14+8], payload[15+8]);
                        insights.push(format!("Source IPv6: {}", src_ip));
                    }
                },
                _ => {
                    insights.push(format!("Unknown EtherType: 0x{:04x}", protocol_type));
                }
            }
        } else if payload.len() >= 2 {
            if payload[0] == 0x08 && payload[1] == 0x00 {
                insights.push("Possible IPv4 packet (no LLC)".to_string());
            } else if payload[0] == 0x86 && payload[1] == 0xDD {
                insights.push("Possible IPv6 packet (no LLC)".to_string());
            } else if payload[0] == 0x08 && payload[1] == 0x06 {
                insights.push("Possible ARP packet (no LLC)".to_string());
            }
        }
    }
    
    if insights.is_empty() {
        insights.push("Encrypted or unknown data".to_string());
    }
    
    insights
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

fn aggressive_ssid_discovery(interface_name: &str) -> Result<HashMap<String, String>, String> {
    println!("Starting aggressive SSID discovery (45 seconds)...");
    println!("This will attempt to uncover hidden networks...");
    
    let frames = capture_and_parse(interface_name, 45000, None)?;
    
    let mut mac_to_ssid = HashMap::new();
    let mut client_to_ap = HashMap::new();
    let mut hidden_ap_count = 0;
    
    for frame in &frames {
        if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
            if !mac_to_ssid.contains_key(bssid) {
                if ssid != "<hidden>" {
                    mac_to_ssid.insert(bssid.clone(), ssid.clone());
                } else {
                    hidden_ap_count += 1;
                }
            }
        }
        
        if let FrameType::Data(_) = &frame.frame_type {
            if let Some(bssid) = &frame.bssid {
                let client = if &frame.mac_src != bssid {
                    Some(frame.mac_src.clone())
                } else if &frame.mac_dst != bssid {
                    Some(frame.mac_dst.clone())
                } else {
                    None
                };
                
                if let Some(client_mac) = client {
                    client_to_ap.entry(client_mac)
                        .or_insert_with(Vec::new)
                        .push(bssid.clone());
                }
            }
        }
    }
    
    for frame in &frames {
        match &frame.frame_type {
            FrameType::Management(ManagementSubtype::ProbeRequest) => {
                if let Some(ssid) = &frame.ssid {
                    if ssid != "<hidden>" && !ssid.is_empty() {
                        let client_mac = frame.mac_src.clone();
                        
                        if let Some(aps) = client_to_ap.get(&client_mac) {
                            for ap_mac in aps {
                                if !mac_to_ssid.contains_key(ap_mac) || mac_to_ssid.get(ap_mac).unwrap() == "<hidden>" {
                                    mac_to_ssid.insert(ap_mac.clone(), format!("{}? (probable)", ssid));
                                    println!("Potential hidden SSID match: {} -> {}", ap_mac, ssid);
                                }
                            }
                        }
                    }
                }
            },
            FrameType::Management(ManagementSubtype::ProbeResponse) => {
                if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
                    if ssid != "<hidden>" {
                        mac_to_ssid.insert(bssid.clone(), ssid.clone());
                    }
                }
            },
            FrameType::Management(ManagementSubtype::AssociationRequest) => {
                if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
                    if ssid != "<hidden>" {
                        mac_to_ssid.insert(bssid.clone(), ssid.clone());
                        println!("Discovered hidden SSID from Association: {} -> {}", bssid, ssid);
                    }
                }
            },
            _ => {}
        }
    }
    
    println!("Aggressive discovery complete.");
    println!("Found {} networks total, including {} with hidden SSIDs", 
             mac_to_ssid.len() + hidden_ap_count, hidden_ap_count);
    println!("Uncovered {} previously hidden networks", 
             mac_to_ssid.values().filter(|s| s.contains("probable")).count());
    
    Ok(mac_to_ssid)
}
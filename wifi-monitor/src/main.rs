use std::env;
use std::process;
use std::time::Duration;
use pcap::{Device, Capture};
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::path::Path;
use std::io::{self, Write, BufWriter};
use chrono::Local;

mod interface;
mod parser;
mod capture;
mod display;
mod web;
mod decryption;

use interface::WifiInterface;
use parser::{capture_and_parse, get_access_points, ParsedFrame};
use display::{display_results, log_to_file};
use std::collections::HashMap;
use parser::{FrameType, ManagementSubtype, DataSubtype};
use decryption::Decryptor;

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("Starting WiFi Packet Capture Tool (Wireshark-like)...");

    if !check_root_privileges() {
        eprintln!("Error: This application requires root privileges.");
        eprintln!("Please run with sudo or as root.");
        process::exit(1);
    }
    
    let args: Vec<String> = env::args().collect();
    let mut interface_name = String::new();
    let mut output_file = None;
    let mut display_filter = None;
    let mut capture_filter = None;
    let mut max_packets = 0; 
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--interface" => {
                if i + 1 < args.len() {
                    interface_name = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: Interface name required after -i");
                    process::exit(1);
                }
            },
            "-w" | "--write" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Output file required after -w");
                    process::exit(1);
                }
            },
            "-f" | "--filter" => {
                if i + 1 < args.len() {
                    capture_filter = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Filter expression required after -f");
                    process::exit(1);
                }
            },
            "-d" | "--display-filter" => {
                if i + 1 < args.len() {
                    display_filter = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Display filter required after -d");
                    process::exit(1);
                }
            },
            "-c" | "--count" => {
                if i + 1 < args.len() {
                    max_packets = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else {
                    eprintln!("Error: Packet count required after -c");
                    process::exit(1);
                }
            },
            "-h" | "--help" => {
                print_usage(&args[0]);
                process::exit(0);
            },
            _ => {
                if interface_name.is_empty() {
                    interface_name = args[i].clone();
                }
                i += 1;
            }
        }
    }
    
    if interface_name.is_empty() {
        match find_wifi_interface() {
            Some(interface) => {
                println!("Auto-detected Wi-Fi interface: {}", interface);
                interface_name = interface;
            },
            None => {
                eprintln!("Error: No Wi-Fi interface found. Please specify one.");
                print_usage(&args[0]);
                process::exit(1);
            }
        }
    }

    let interface = WifiInterface::new(&interface_name);
    println!("Using interface: {}", interface.get_interface_name());

    println!("Setting interface to monitor mode...");
    if let Err(e) = interface.set_monitor_mode() {
        eprintln!("Failed to set monitor mode: {}", e);
        return Err(e);
    }
    println!("Interface is now in monitor mode");

    let hopping_interface = interface_name.clone();
    let _channel_hopper = std::thread::spawn(move || {
        channel_hopping(&hopping_interface);
    });

    let mut pcap_writer = if let Some(file_path) = &output_file {
        println!("Saving capture to file: {}", file_path);
        Some(create_pcap_file(file_path)?)
    } else {
        None
    };

    let interface_clone = interface_name.clone();
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        
        let cleanup_interface = WifiInterface::new(&interface_clone);
        if let Err(e) = cleanup_interface.set_managed_mode() {
            eprintln!("Warning: Failed to restore managed mode: {}", e);
        } else {
            println!("Interface restored to managed mode");
        }
        
        if let Some(file_path) = &output_file {
            println!("Capture saved to: {}", file_path);
        }
        
        process::exit(0);
    }).expect("Error setting Ctrl+C handler");

    println!("Starting packet capture (press Ctrl+C to stop)...");
    println!("{:<4} {:<19} {:<19} {:<19} {:<8} {:<10} {:<30}", 
             "No.", "Time", "Source", "Destination", "Length", "Protocol", "Info");
    println!("{:-<100}", "");

    let mut packet_count = 0;
    loop {
        match capture_and_parse(&interface_name, 1000, capture_filter.as_deref()) {
            Ok(frames) => {
                for frame in &frames {
                    if let Some(ref filter) = display_filter {
                        if !matches_display_filter(frame, filter) {
                            continue;
                        }
                    }
                    
                    if let Some(ref mut writer) = pcap_writer {
                        if let Some(ref raw_data) = frame.raw_data {
                            write_packet_to_pcap(writer, raw_data)?;
                        }
                    }
                    
                    display_wireshark_style(packet_count + 1, frame);
                    packet_count += 1;
                    
                    if max_packets > 0 && packet_count >= max_packets {
                        println!("\nCaptured {} packets. Stopping.", max_packets);
                        let cleanup_interface = WifiInterface::new(&interface_name);
                        if let Err(e) = cleanup_interface.set_managed_mode() {
                            eprintln!("Warning: Failed to restore managed mode: {}", e);
                        } else {
                            println!("Interface restored to managed mode");
                        }
                        return Ok(());
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

fn print_usage(program_name: &str) {
    println!("Usage: {} [OPTIONS] [INTERFACE]", program_name);
    println!("Options:");
    println!("  -i, --interface <iface>   Specify WiFi interface to use");
    println!("  -w, --write <file>        Save captured packets to file");
    println!("  -f, --filter <expr>       Set capture filter");
    println!("  -d, --display-filter <expr>  Set display filter");
    println!("  -c, --count <num>         Capture num packets and exit");
    println!("  -h, --help                Show this help message");
    println!("\nExamples:");
    println!("  {} wlan1                  Capture on wlan1", program_name);
    println!("  {} -i wlan1 -w capture.pcap  Save to file", program_name);
    println!("  {} -f \"wlan type mgt\"      Filter management frames", program_name);
}

// PCAP file creation for logging data and other stuff
fn create_pcap_file(file_path: &str) -> Result<BufWriter<File>, String> {
    let file = File::create(file_path)
        .map_err(|e| format!("Failed to create capture file: {}", e))?;
    
    let mut writer = BufWriter::new(file);
    
    writer.write_all(&[0xa1, 0xb2, 0xc3, 0xd4]).map_err(|e| e.to_string())?;
    writer.write_all(&[2, 0]).map_err(|e| e.to_string())?;
    writer.write_all(&[4, 0]).map_err(|e| e.to_string())?;
    writer.write_all(&[0, 0, 0, 0]).map_err(|e| e.to_string())?;
    writer.write_all(&[0, 0, 0, 0]).map_err(|e| e.to_string())?;
    writer.write_all(&[0xff, 0xff, 0, 0]).map_err(|e| e.to_string())?;
    writer.write_all(&[127, 0, 0, 0]).map_err(|e| e.to_string())?;
    
    Ok(writer)
}

fn write_packet_to_pcap(writer: &mut BufWriter<File>, packet_data: &[u8]) -> Result<(), String> {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    
    let ts_sec = duration.as_secs() as u32;
    writer.write_all(&ts_sec.to_le_bytes()).map_err(|e| e.to_string())?;
    
    let ts_usec = duration.subsec_micros();
    writer.write_all(&ts_usec.to_le_bytes()).map_err(|e| e.to_string())?;
    
    let caplen = packet_data.len() as u32;
    writer.write_all(&caplen.to_le_bytes()).map_err(|e| e.to_string())?;
    
    writer.write_all(&caplen.to_le_bytes()).map_err(|e| e.to_string())?;
    
    writer.write_all(packet_data).map_err(|e| e.to_string())?;
    
    Ok(())
}

fn matches_display_filter(frame: &ParsedFrame, filter: &str) -> bool {
    let filter = filter.to_lowercase();
    
    if filter.contains("type") {
        match &frame.frame_type {
            FrameType::Management(_) if filter.contains("management") || filter.contains("mgt") => return true,
            FrameType::Control(_) if filter.contains("control") || filter.contains("ctl") => return true,
            FrameType::Data(_) if filter.contains("data") => return true,
            _ => {}
        }
    }
    
    if let Some(ref mac_src) = frame.mac_src {
        if filter.contains(mac_src) {
            return true;
        }
    }
    
    if let Some(ref mac_dst) = frame.mac_dst {
        if filter.contains(mac_dst) {
            return true;
        }
    }
    
    if let Some(ref bssid) = frame.bssid {
        if filter.contains(bssid) {
            return true;
        }
    }
    
    if let Some(ref ssid) = frame.ssid {
        if filter.contains(ssid) {
            return true;
        }
    }
    
    filter.is_empty()
}

fn display_wireshark_style(num: usize, frame: &ParsedFrame) {
    let timestamp = Local::now().format("%H:%M:%S%.6f").to_string();
    
    let source = frame.mac_src.clone().unwrap_or_else(|| "??:??:??:??:??:??".to_string());
    let dest = frame.mac_dst.clone().unwrap_or_else(|| "??:??:??:??:??:??".to_string());
    
    let length = frame.frame_length;
    
    let protocol = match &frame.frame_type {
        FrameType::Management(subtype) => format!("802.11 Mgmt {}", format_mgmt_subtype(subtype)),
        FrameType::Control(subtype) => format!("802.11 Ctrl {:?}", subtype),
        FrameType::Data(subtype) => format!("802.11 Data {:?}", subtype),
        FrameType::Extension(subtype) => format!("802.11 Ext {:?}", subtype),
    };
    
    let info = get_frame_info(frame);
    
    println!("{:<4} {:<19} {:<19} {:<19} {:<8} {:<10} {:<30}", 
             num, timestamp, source, dest, length, protocol, info);
}

fn format_mgmt_subtype(subtype: &ManagementSubtype) -> String {
    match subtype {
        ManagementSubtype::Beacon => "Beacon".to_string(),
        ManagementSubtype::ProbeRequest => "Probe Req".to_string(),
        ManagementSubtype::ProbeResponse => "Probe Resp".to_string(),
        ManagementSubtype::Authentication => "Auth".to_string(),
        ManagementSubtype::Deauthentication => "Deauth".to_string(),
        ManagementSubtype::AssociationRequest => "Assoc Req".to_string(),
        ManagementSubtype::AssociationResponse => "Assoc Resp".to_string(),
        ManagementSubtype::ReassociationRequest => "Reassoc Req".to_string(),
        ManagementSubtype::ReassociationResponse => "Reassoc Resp".to_string(),
        ManagementSubtype::Disassociation => "Disassoc".to_string(),
        _ => format!("{:?}", subtype),
    }
}

fn get_frame_info(frame: &ParsedFrame) -> String {
    match &frame.frame_type {
        FrameType::Management(ManagementSubtype::Beacon) => {
            if let Some(ref ssid) = frame.ssid {
                if ssid == "<hidden>" {
                    format!("BSSID: {}", frame.bssid.as_deref().unwrap_or("??"))
                } else {
                    format!("SSID: {}", ssid)
                }
            } else {
                "Beacon frame".to_string()
            }
        },
        FrameType::Management(ManagementSubtype::ProbeRequest) => {
            if let Some(ref ssid) = frame.ssid {
                if ssid.is_empty() {
                    "Wildcard Probe Request".to_string()
                } else {
                    format!("Probe Request for \"{}\"", ssid)
                }
            } else {
                "Probe Request".to_string()
            }
        },
        FrameType::Management(ManagementSubtype::ProbeResponse) => {
            if let Some(ref ssid) = frame.ssid {
                format!("Probe Response for \"{}\"", ssid)
            } else {
                "Probe Response".to_string()
            }
        },
        FrameType::Management(ManagementSubtype::Deauthentication) => {
            format!("Deauthentication, BSSID: {}", 
                    frame.bssid.as_deref().unwrap_or("??"))
        },
        FrameType::Data(_) => {
            if let Some(ref payload) = frame.payload {
                if payload.len() > 0 {
                    let mut insights = analyze_data_packet(frame);
                    if !insights.is_empty() {
                        insights.first().unwrap().clone()
                    } else {
                        format!("Data, {} bytes", frame.frame_length)
                    }
                } else {
                    format!("Data, {} bytes", frame.frame_length)
                }
            } else {
                format!("Data, {} bytes", frame.frame_length)
            }
        },
        _ => format!("{:?}", frame.frame_type),
    }
}

fn channel_hopping(interface: &str) {
    let wifi = WifiInterface::new(interface);
    let channels_2ghz = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13];
    let channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];
    
    println!("Starting channel hopping on both 2.4GHz and 5GHz bands");
    
    let supports_5ghz = wifi.set_channel(36).is_ok();
    if supports_5ghz {
        println!("Adapter supports 5GHz! Will scan both bands.");
    } else {
        println!("Adapter appears to only support 2.4GHz. Limited to those channels.");
    }
    
    loop {
        for &channel in &channels_2ghz {
            if let Err(e) = wifi.set_channel(channel) {
                eprintln!("Failed to set 2.4GHz channel {}: {}", channel, e);
            } else {
                println!("Hopping to channel {} (2.4GHz)", channel);
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        
        if supports_5ghz {
            for &channel in &channels_5ghz {
                if let Err(e) = wifi.set_channel(channel) {
                    if !e.contains("Invalid argument") {
                        eprintln!("Failed to set 5GHz channel {}: {}", channel, e);
                    }
                } else {
                    println!("Hopping to channel {} (5GHz)", channel);
                }
                std::thread::sleep(Duration::from_millis(1000));
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

fn lock_to_channel(interface_name: &str, channel: u8) -> Result<(), String> {
    println!("Locking to channel {} for continuous monitoring", channel);
    
    let wifi = WifiInterface::new(interface_name);
    if let Err(e) = wifi.set_channel(channel) {
        return Err(format!("Failed to set channel: {}", e));
    }
    
    Ok(())
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
                        let ip_header_len = (payload[8] & 0x0F) as usize * 4; 
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
                                        let offset = 8 + ip_header_len; 
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
                                    if payload.len() >= 8 + ip_header_len + 4 { // And this one
                                        let offset = 8 + ip_header_len;
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
    println!("Starting network discovery phase (30 seconds)...");
    
    let frames = capture_and_parse(interface_name, 30000, None)?;
    
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

// Function for decryption 
fn setup_decryption() -> Decryptor {
    let mut decryptor = Decryptor::new();
    
    println!("\n--- WiFi Decryption Setup ---");
    println!("To decrypt traffic, you need to provide the SSID and password for networks you own.");
    
    loop {
        print!("\nEnter network SSID (or leave empty to finish): ");
        io::stdout().flush().unwrap();
        let mut ssid = String::new();
        io::stdin().read_line(&mut ssid).expect("Failed to read input");
        let ssid = ssid.trim();
        
        if ssid.is_empty() {
            break;
        }
        
        print!("Enter network password: ");
        io::stdout().flush().unwrap();
        let mut password = String::new();
        io::stdin().read_line(&mut password).expect("Failed to read input");
        let password = password.trim();
        
        print!("Enter network BSSID (MAC address) if known (or leave empty): ");
        io::stdout().flush().unwrap();
        let mut bssid = String::new();
        io::stdin().read_line(&mut bssid).expect("Failed to read input");
        let bssid = bssid.trim();
        
        if !password.is_empty() {
            decryptor.add_network(ssid, password);
            
            if !bssid.is_empty() {
                MANUAL_BSSIDS.lock().unwrap().insert(bssid.to_string(), ssid.to_string());
                println!("Added manual BSSID mapping: {} -> {}", bssid, ssid);
            }
        }
    }
    
    println!("Decryption setup complete.");
    decryptor
}

fn build_capture_filter(decryptor: &Decryptor, mac_to_ssid: &HashMap<String, String>) -> Option<String> {
    let target_ssids: Vec<&String> = decryptor.network_keys.keys().collect();
    
    if target_ssids.is_empty() {
        println!("No specific networks provided - capturing all networks");
        return None;
    }
    
    println!("\nDiscovered networks:");
    for (bssid, ssid) in mac_to_ssid {
        println!("  • {} ({})", ssid, bssid);
    }
    
    // Find BSSIDs (MAC addresses) for these SSIDs
    let mut target_bssids = Vec::new();
    for (bssid, ssid) in mac_to_ssid {
        if target_ssids.iter().any(|&s| s.to_lowercase() == ssid.to_lowercase()) {
            target_bssids.push(bssid.clone());
        }
    }
    
    if target_bssids.is_empty() {
        println!("\nCouldn't find target networks in discovery scan.");
        println!("Attempting to get BSSID of currently connected network...");
        
        if let Some(connected_bssid) = get_connected_bssid("wlan1") {
            println!("Found connected network BSSID: {}", connected_bssid);
            target_bssids.push(connected_bssid);
        } else {
            println!("Couldn't determine connected network BSSID.");
            println!("Capturing all traffic to discover target network.");
            return None;
        }
    }
    
    let mut filter = String::new();
    
    for (i, bssid) in target_bssids.iter().enumerate() {
        if i > 0 {
            filter.push_str(" or ");
        }
        filter.push_str(&format!("(wlan addr1 {} or wlan addr2 {} or wlan addr3 {})", 
                             bssid, bssid, bssid));
    }
    
    println!("\nFiltering capture to only include packets from your networks:");
    for bssid in &target_bssids {
        if let Some(ssid) = mac_to_ssid.get(bssid) {
            println!("  • {} ({})", ssid, bssid);
        } else {
            println!("  • Unknown BSSID: {} (looking for: {})", 
                     bssid, 
                     target_ssids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
    }
    
    Some(filter)
}

fn get_connected_bssid(interface_name: &str) -> Option<String> {
    let output = match std::process::Command::new("iw")
        .arg("dev")
        .arg(interface_name) 
        .arg("link")
        .output() {
            Ok(o) => o,
            Err(_) => return None,
        };
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains("Connected to") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts[2].to_string());
            }
        }
    }
    
    None
}

fn wait_for_handshakes(interface_name: &str, decryptor: &mut Decryptor, mac_to_ssid: &HashMap<String, String>) -> Result<(), String> {
    println!("\n--- Waiting for Network Handshakes ---");
    println!("Attempting to capture authentication handshakes for your networks.");
    println!("This may take some time until devices connect to the network.");
    println!("Capturing for up to 60 seconds...");
    
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(60);
    
    while start_time.elapsed() < timeout {
        print!(".");
        io::stdout().flush().unwrap();
        
        match capture_and_parse(interface_name, 5000, None) {
            Ok(frames) => {
                for frame in &frames {
                    decryptor.process_packet(frame, mac_to_ssid);
                }
                
                let mut have_all_keys = true;
                for ssid in decryptor.network_keys.keys() {
                    let found = mac_to_ssid.iter().any(|(bssid, net_ssid)| {
                        net_ssid == ssid && decryptor.decryption_keys.contains_key(bssid)
                    });
                    
                    if !found {
                        have_all_keys = false;
                        break;
                    }
                }
                
                if have_all_keys && !decryptor.network_keys.is_empty() {
                    println!("\nSuccessfully captured handshakes for all networks!");
                    return Ok(());
                }
            },
            Err(_) => {
            }
        }
    }
    
    println!("\nFinished waiting for handshakes.");
    if decryptor.decryption_keys.is_empty() {
        println!("No handshakes captured. Decryption will begin when handshakes are seen.");
    } else {
        println!("Captured handshakes for some networks. Monitoring will continue.");
    }
    
    Ok(())
}

fn send_probe_requests(interface_name: &str, target_ssids: &[String]) -> Result<(), String> {
    println!("🔍 Sending probe requests to actively discover networks...");
    println!("This is a more aggressive technique that will make networks respond.");
    
    let mac_addr = get_interface_mac(interface_name)?;
    println!("Using interface MAC: {}", mac_addr);
    
    if !target_ssids.is_empty() {
        for ssid in target_ssids {
            println!("Probing for network: {}", ssid);
            send_probe_request(interface_name, ssid, &mac_addr)?;
            std::thread::sleep(Duration::from_millis(200));
            send_probe_request(interface_name, ssid, &mac_addr)?;
            std::thread::sleep(Duration::from_millis(300));
        }
    } else {
        println!("Sending broadcast probe request");
        send_probe_request(interface_name, "", &mac_addr)?;
        std::thread::sleep(Duration::from_millis(200));
        send_probe_request(interface_name, "", &mac_addr)?;
    }
    
    println!("Probe requests sent successfully.");
    Ok(())
}

fn send_probe_request(interface_name: &str, ssid: &str, src_mac: &str) -> Result<(), String> {
    println!("Sending probe request for SSID: \"{}\"", if ssid.is_empty() { "[Broadcast]" } else { ssid });
    
    let src_mac_bytes = mac_str_to_bytes(src_mac)
        .map_err(|_| format!("Invalid MAC address format: {}", src_mac))?;
    
    let broadcast_addr: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    
    let mut frame = Vec::new();
    
    frame.push(0x40); 
    frame.push(0x00); 
    
    frame.push(0x00);
    frame.push(0x00);
    
    frame.extend_from_slice(&broadcast_addr);
    frame.extend_from_slice(&src_mac_bytes);
    frame.extend_from_slice(&broadcast_addr);
    
    frame.push(0x00);
    frame.push(0x00);
    
    frame.push(0x00); 
    frame.push(ssid.len() as u8); 
    frame.extend_from_slice(ssid.as_bytes()); 
    
    frame.push(0x01); // Element ID: Supported Rates
    frame.push(0x08); // Length
    frame.push(0x82); // 1 Mbps (basic rate)
    frame.push(0x84); // 2 Mbps (basic rate)
    frame.push(0x8B); // 5.5 Mbps (basic rate)
    frame.push(0x96); // 11 Mbps (basic rate)
    frame.push(0x0C); // 6 Mbps
    frame.push(0x12); // 9 Mbps
    frame.push(0x18); // 12 Mbps
    frame.push(0x24); // 18 Mbps
    
    frame.push(0x32); // Element ID: Extended Supported Rates
    frame.push(0x04); // Length
    frame.push(0x30); // 24 Mbps
    frame.push(0x48); // 36 Mbps
    frame.push(0x60); // 48 Mbps
    frame.push(0x6C); // 54 Mbps
    
    inject_raw_frame(interface_name, &frame)
}

// Better deauth func
fn deauthenticate_network(interface_name: &str, bssid: &str) -> Result<(), String> {
    println!("🔥 Sending deauthentication packets to network: {}", bssid);
    println!("This will force connected devices to reconnect, generating handshakes.");
    
    let bssid_bytes = mac_str_to_bytes(bssid)
        .map_err(|_| format!("Invalid BSSID format: {}", bssid))?;
    
    let broadcast_addr: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    
    let mut frame = Vec::new();
    
    frame.push(0xC0);
    frame.push(0x00); 
    frame.push(0x00);
    frame.push(0x00);
    frame.extend_from_slice(&broadcast_addr);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x01);
    frame.push(0x00);
    
    for i in 0..5 {
        println!("Sending deauth frame {}/5...", i+1);
        inject_raw_frame(interface_name, &frame)?;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    println!("Deauthentication packets sent successfully.");
    Ok(())
}

fn mac_str_to_bytes(mac: &str) -> Result<[u8; 6], &'static str> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err("Invalid MAC address format");
    }
    
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).map_err(|_| "Invalid hex in MAC address")?;
    }
    
    Ok(bytes)
}


fn add_radiotap_header(frame: &[u8]) -> Vec<u8> {
    let mut complete_frame = Vec::new();
    
    complete_frame.push(0x00);
    complete_frame.push(0x00);
    complete_frame.push(0x08);
    complete_frame.push(0x00);
    complete_frame.push(0x00);
    complete_frame.push(0x00);
    complete_frame.push(0x00);
    complete_frame.push(0x00);
    
    complete_frame.extend_from_slice(frame);
    
    complete_frame
}


fn inject_raw_frame(interface_name: &str, frame_data: &[u8]) -> Result<(), String> {
    let complete_frame = add_radiotap_header(frame_data);
    
    let devices = pcap::Device::list()
        .map_err(|e| format!("Failed to list devices: {}", e))?;
    
    let device = devices.into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Device {} not found", interface_name))?;
    
    let mut cap = pcap::Capture::from_device(device)
        .map_err(|e| format!("Failed to open device: {}", e))?
        .promisc(true)
        .rfmon(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;
    
    cap.sendpacket(&*complete_frame)
        .map_err(|e| format!("Failed to send packet: {}", e))?;
    
    println!("Successfully sent {} byte frame (with {} byte RadioTap header)", 
             complete_frame.len(), complete_frame.len() - frame_data.len());
    Ok(())
}

fn get_interface_mac(interface_name: &str) -> Result<String, String> {
    let output = match std::process::Command::new("ip")
        .arg("link")
        .arg("show")
        .arg(interface_name)
        .output() {
            Ok(output) => output,
            Err(_) => {
                return match std::process::Command::new("ifconfig")
                    .arg(interface_name)
                    .output() {
                        Ok(output) => parse_ifconfig_output(&output.stdout, interface_name),
                        Err(e) => Err(format!("Failed to get interface MAC: {}", e)),
                    };
            }
        };

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains("link/ether") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].to_string());
            }
        }
    }
    
    Err(format!("Could not determine MAC address for {}", interface_name))
}

fn parse_ifconfig_output(output: &[u8], interface_name: &str) -> Result<String, String> {
    let output_str = String::from_utf8_lossy(output);
    for line in output_str.lines() {
        if line.contains("ether") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                for (i, part) in parts.iter().enumerate() {
                    if *part == "ether" && i + 1 < parts.len() {
                        return Ok(parts[i + 1].to_string());
                    }
                }
            }
        }
    }
    
    Err(format!("Could not find MAC address in ifconfig output for {}", interface_name))
}
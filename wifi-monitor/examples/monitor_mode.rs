use pcap::{Capture, Device};
use std::process::Command;
use std::time::Duration;

fn main() {
    match find_wifi_interface() {
        Some(interface) => {
            println!("Found Wi-Fi interface: {}", interface);
            if set_monitor_mode(&interface).is_ok() {
                println!("Successfully set {} to monitor mode.", interface);
                
                if let Err(e) = capture_frames(&interface) {
                    eprintln!("Error capturing frames: {}", e);
                }
                
                if let Err(e) = set_managed_mode(&interface) {
                    eprintln!("Error restoring managed mode: {}", e);
                }
            } else {
                eprintln!("Failed to set {} to monitor mode.", interface);
            }
        },
        None => {
            eprintln!("No suitable Wi-Fi interface found.");
        }
    }
}

fn find_wifi_interface() -> Option<String> {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(_) => return None,
    };
    
    for device in devices {
        let name = device.name;
        if name.starts_with("wlan") || name.contains("wl") {
            return Some(name);
        }
    }
    
    None
}

fn set_monitor_mode(interface: &str) -> Result<(), String> {
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("down")
        .output()
        .map_err(|e| e.to_string())?;

    Command::new("sudo")
        .arg("iw")
        .arg(interface)
        .arg("set")
        .arg("type")
        .arg("monitor")
        .output()
        .map_err(|e| e.to_string())?;

    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("up")
        .output()
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn set_managed_mode(interface: &str) -> Result<(), String> {
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("down")
        .output()
        .map_err(|e| e.to_string())?;

    Command::new("sudo")
        .arg("iw")
        .arg(interface)
        .arg("set")
        .arg("type")
        .arg("managed")
        .output()
        .map_err(|e| e.to_string())?;

    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("up")
        .output()
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn capture_frames(interface: &str) -> Result<(), String> {
    let mut cap = Capture::from_device(interface)
        .map_err(|e| e.to_string())?
        .promisc(true)  
        .snaplen(2048)  
        .timeout(1000)  
        .open()
        .map_err(|e| e.to_string())?;
    
    println!("Starting packet capture on {}", interface);
    println!("Press Ctrl+C to stop capturing...");
    
    let max_packets = 100;
    let mut packet_count = 0;
    
    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        
        parse_packet(&packet);
        
        if packet_count >= max_packets {
            break;
        }
    }
    
    println!("Capture completed. Processed {} packets.", packet_count);
    Ok(())
}

fn parse_packet(packet: &pcap::Packet) {
    let data = packet.data;
    if data.len() < 4 {
        println!("Packet too short to be a valid 802.11 frame");
        return;
    }
    
    let radiotap_len = (data[2] as usize) | ((data[3] as usize) << 8);
    
    if data.len() < radiotap_len {
        println!("Packet too short to contain full radiotap header");
        return;
    }
    
    let frame_data = &data[radiotap_len..];
    if frame_data.len() < 24 {  
        println!("802.11 frame too short");
        return;
    }
    
    let frame_control = frame_data[0];
    let frame_type = (frame_control & 0x0C) >> 2;
    let frame_subtype = (frame_control & 0xF0) >> 4;
    
    println!("Packet: Type={}, Subtype={}, Length={} bytes", 
             frame_type_to_string(frame_type),
             frame_subtype,
             data.len());
    
    if (frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5)) && frame_data.len() >= 38 {
        let mut current_pos = 24;
        
        while current_pos + 2 < frame_data.len() {
            let tag_number = frame_data[current_pos];
            let tag_length = frame_data[current_pos + 1] as usize;
            
            if tag_number == 0 && current_pos + 2 + tag_length <= frame_data.len() {
                if tag_length > 0 {
                    let ssid = String::from_utf8_lossy(&frame_data[current_pos + 2..current_pos + 2 + tag_length]);
                    println!("  SSID: {}", ssid);
                } else {
                    println!("  SSID: <hidden>");
                }
                break;
            }
            
            current_pos += 2 + tag_length;
            if current_pos >= frame_data.len() {
                break;
            }
        }
    }
    
    if frame_data.len() >= 30 {
        println!("  Destination: {}", format_mac_address(&frame_data[4..10]));
        println!("  Source: {}", format_mac_address(&frame_data[10..16]));
        println!("  BSSID: {}", format_mac_address(&frame_data[16..22]));
    }
    
    println!(""); 
}

fn frame_type_to_string(frame_type: u8) -> &'static str {
    match frame_type {
        0 => "Management",
        1 => "Control",
        2 => "Data",
        3 => "Extension",
        _ => "Unknown",
    }
}

fn format_mac_address(mac: &[u8]) -> String {
    if mac.len() < 6 {
        return "Invalid MAC".to_string();
    }
    
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
use pcap::{Capture, Device, Packet};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ParsedFrame {
    pub frame_type: FrameType,
    pub mac_src: String,
    pub mac_dst: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub rssi: Option<i8>,
    pub channel: Option<u8>,
    pub timestamp: std::time::SystemTime,
    pub sequence_number: Option<u16>,
    pub frequency: Option<u16>,
    pub payload: Option<Vec<u8>>,
    pub frame_length: usize,
    pub security: Option<SecurityType>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FrameType {
    Management(ManagementSubtype),
    Control(ControlSubtype),
    Data(DataSubtype),
    Extension,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlSubtype {
    BeamformingReportPoll,
    VhtNdpAnnouncement,
    ControlFrameExtension,
    ControlWrapper,
    BlockAckRequest,
    BlockAck,
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    CfEndCfAck,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataSubtype {
    Data,
    DataCfAck,
    DataCfPoll,
    DataCfAckCfPoll,
    Null,
    CfAck,
    CfPoll,
    CfAckCfPoll,
    QosData,
    QosDataCfAck,
    QosDataCfPoll,
    QosDataCfAckCfPoll,
    QosNull,
    QosCfPoll,
    QosCfAckCfPoll,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityType {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    Unknown,
}

/// Main parser function
pub fn parse_packet(packet: &Packet) -> Option<ParsedFrame> {
    let data = packet.data;
    
    if data.len() < 4 {
        return None;
    }
    
    let (radiotap_len, rssi, channel) = parse_radiotap_header(data)?;
    
    let frame_data = &data[radiotap_len..];
    if frame_data.len() < 24 {  
        return None;
    }
    
    let frame_control = frame_data[0];
    let frame_type_val = (frame_control & 0x0C) >> 2;
    let frame_subtype_val = (frame_control & 0xF0) >> 4;
    
    let frame_type = match frame_type_val {
        0 => {
            // Management frame
            let subtype = match frame_subtype_val {
                0 => ManagementSubtype::AssociationRequest,
                1 => ManagementSubtype::AssociationResponse,
                2 => ManagementSubtype::ReassociationRequest,
                3 => ManagementSubtype::ReassociationResponse,
                4 => ManagementSubtype::ProbeRequest,
                5 => ManagementSubtype::ProbeResponse,
                8 => ManagementSubtype::Beacon,
                9 => ManagementSubtype::Atim,
                10 => ManagementSubtype::Disassociation,
                11 => ManagementSubtype::Authentication,
                12 => ManagementSubtype::Deauthentication,
                13 => ManagementSubtype::Action,
                14 => ManagementSubtype::ActionNoAck,
                _ => ManagementSubtype::Other(frame_subtype_val),
            };
            FrameType::Management(subtype)
        },
        1 => {
            // Control frame
            let subtype = match frame_subtype_val {
                4 => ControlSubtype::BeamformingReportPoll,
                5 => ControlSubtype::VhtNdpAnnouncement,
                6 => ControlSubtype::ControlFrameExtension,
                7 => ControlSubtype::ControlWrapper,
                8 => ControlSubtype::BlockAckRequest,
                9 => ControlSubtype::BlockAck,
                10 => ControlSubtype::PsPoll,
                11 => ControlSubtype::Rts,
                12 => ControlSubtype::Cts,
                13 => ControlSubtype::Ack,
                14 => ControlSubtype::CfEnd,
                15 => ControlSubtype::CfEndCfAck,
                _ => ControlSubtype::Other(frame_subtype_val),
            };
            FrameType::Control(subtype)
        },
        2 => {
            // Data frame
            let subtype = match frame_subtype_val {
                0 => DataSubtype::Data,
                1 => DataSubtype::DataCfAck,
                2 => DataSubtype::DataCfPoll,
                3 => DataSubtype::DataCfAckCfPoll,
                4 => DataSubtype::Null,
                5 => DataSubtype::CfAck,
                6 => DataSubtype::CfPoll,
                7 => DataSubtype::CfAckCfPoll,
                8 => DataSubtype::QosData,
                9 => DataSubtype::QosDataCfAck,
                10 => DataSubtype::QosDataCfPoll,
                11 => DataSubtype::QosDataCfAckCfPoll,
                12 => DataSubtype::QosNull,
                14 => DataSubtype::QosCfPoll,
                15 => DataSubtype::QosCfAckCfPoll,
                _ => DataSubtype::Other(frame_subtype_val),
            };
            FrameType::Data(subtype)
        },
        3 => FrameType::Extension,
        _ => FrameType::Unknown,
    };
    
    let mac_dst = format_mac_address(&frame_data[4..10]);
    let mac_src = format_mac_address(&frame_data[10..16]);
    
    let bssid = if frame_data.len() >= 22 {
        Some(format_mac_address(&frame_data[16..22]))
    } else {
        None
    };
    
    let ssid = match &frame_type {
        FrameType::Management(ManagementSubtype::Beacon) | 
        FrameType::Management(ManagementSubtype::ProbeResponse) => {
            extract_ssid(frame_data)
        },
        _ => None,
    };
    
    let sequence_number = if frame_data.len() >= 24 {
        Some(((frame_data[22] as u16) >> 4) | ((frame_data[23] as u16) << 4))
    } else {
        None
    };
    
    let frequency = if channel.is_some() {
        let ch = channel.unwrap() as u16;
        if ch <= 14 {
            Some(2407 + ch * 5) 
        } else {
            Some(5000 + ch * 5) 
        }
    } else {
        None
    };
    
    let security = match &frame_type {
        FrameType::Management(ManagementSubtype::Beacon) |
        FrameType::Management(ManagementSubtype::ProbeResponse) => {
            extract_security_info(frame_data)
        },
        _ => None,
    };
    
    // Payload extraction
    let payload = match &frame_type {
        FrameType::Data(_) => {
            let header_size = 24; // Basic size, adjust for QoS/HT frames
            if frame_data.len() > header_size {
                Some(frame_data[header_size..].to_vec())
            } else {
                None
            }
        },
        _ => None,
    };
    
    Some(ParsedFrame {
        frame_type,
        mac_src,
        mac_dst,
        bssid,
        ssid,
        rssi,
        channel,
        timestamp: std::time::SystemTime::now(),
        sequence_number,
        frequency,
        payload,
        frame_length: frame_data.len(),
        security,
    })
}

/// SSID extraction from management frames
fn extract_ssid(frame_data: &[u8]) -> Option<String> {
    if frame_data.len() < 36 {
        return None;
    }
    
    let mut pos = 24;
    
    while pos + 2 < frame_data.len() {
        let tag_number = frame_data[pos];
        let tag_length = frame_data[pos + 1] as usize;
        
        if tag_number == 0 { 
            if tag_length == 0 {
                return Some("<hidden>".to_string());
            } else if pos + 2 + tag_length <= frame_data.len() {
                let ssid_bytes = &frame_data[pos + 2..pos + 2 + tag_length];
                
                if let Ok(ssid) = String::from_utf8(ssid_bytes.to_vec()) {
                    if !ssid.trim().is_empty() {
                        return Some(ssid);
                    }
                }
                
                let readable_ssid: String = ssid_bytes.iter()
                    .map(|&b| if b >= 32 && b <= 126 { b as char } else { '?' })
                    .collect();
                
                let question_count = readable_ssid.chars().filter(|&c| c == '?').count();
                if question_count < readable_ssid.len() / 2 {
                    return Some(format!("{} (non-UTF8)", readable_ssid));
                } else {
                    let hex_ssid = ssid_bytes.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<String>>()
                        .join("");
                    return Some(format!("HEX[{}]", hex_ssid));
                }
            }
        }
        
        pos += 2 + tag_length;
        if pos >= frame_data.len() {
            break;
        }
    }
    
    None
}

/// MAC formatting
fn format_mac_address(mac: &[u8]) -> String {
    if mac.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn parse_radiotap_header(data: &[u8]) -> Option<(usize, Option<i8>, Option<u8>)> {
    if data.len() < 8 {
        return None;
    }
    
    let header_len = (data[2] as usize) | ((data[3] as usize) << 8);
    if data.len() < header_len {
        return None; 
    }
    
    let present_flags = (data[4] as u32) | ((data[5] as u32) << 8) | 
                        ((data[6] as u32) << 16) | ((data[7] as u32) << 24);
    
    const TSFT_PRESENT: u32 = 1 << 0;
    const FLAGS_PRESENT: u32 = 1 << 1;
    const RATE_PRESENT: u32 = 1 << 2;
    const CHANNEL_PRESENT: u32 = 1 << 3;
    const FHSS_PRESENT: u32 = 1 << 4;
    const ANT_SIGNAL_PRESENT: u32 = 1 << 5;
    
    let mut pos = 8; 
    
    if present_flags & TSFT_PRESENT != 0 {
        pos += 8;
    }
    
    if present_flags & FLAGS_PRESENT != 0 {
        pos += 1;
    }
    
    if present_flags & RATE_PRESENT != 0 {
        pos += 1;
    }
    
    let mut channel = None;
    if present_flags & CHANNEL_PRESENT != 0 {
        if pos + 2 <= header_len {
            channel = Some((data[pos] as u16 | ((data[pos+1] as u16) << 8)) as u8);
        }
        pos += 4; 
    }
    
    if present_flags & FHSS_PRESENT != 0 {
        pos += 2;
    }
    
    let mut rssi = None;
    if present_flags & ANT_SIGNAL_PRESENT != 0 {
        if pos < header_len {
            rssi = Some(data[pos] as i8);
        }
    }
    
    Some((header_len, rssi, channel))
}

pub fn capture_and_parse(device_name: &str, timeout_ms: u32, filter: Option<&str>) -> Result<Vec<ParsedFrame>, String> {
    let mut cap = Capture::from_device(device_name)
        .map_err(|e| format!("Failed to open device: {}", e))?
        .promisc(true)
        .snaplen(2048)
        .timeout(timeout_ms.try_into().unwrap())
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;
    
    if let Some(filter_str) = filter {
        cap.filter(filter_str, true)
            .map_err(|e| format!("Failed to set filter: {}", e))?;
    }
    
    let mut frames = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms as u64);
    
    while std::time::Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(frame) = parse_packet(&packet) {
                    frames.push(frame);
                }
            },
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    
    Ok(frames)
}

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub rssi: Option<i8>,
    pub channel: Option<u8>,
    pub last_seen: std::time::SystemTime,
    pub beacon_count: u32,
    pub security: Option<SecurityType>,
}

pub fn get_access_points(frames: &[ParsedFrame]) -> HashMap<String, AccessPoint> {
    let mut aps = HashMap::new();
    
    for frame in frames {
        if let FrameType::Management(ManagementSubtype::Beacon) = &frame.frame_type {
            if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
                let ap = aps.entry(bssid.clone()).or_insert_with(|| AccessPoint {
                    bssid: bssid.clone(),
                    ssid: ssid.clone(),
                    rssi: frame.rssi,
                    channel: frame.channel,
                    last_seen: frame.timestamp,
                    beacon_count: 0,
                    security: frame.security.clone(),
                });
                
                ap.beacon_count += 1;
                if let Some(rssi) = frame.rssi {
                    ap.rssi = Some(rssi);
                }
                ap.last_seen = frame.timestamp;
                if ap.security.is_none() {
                    ap.security = frame.security.clone();
                }
            }
        }
        
        else if let FrameType::Management(ManagementSubtype::ProbeResponse) = &frame.frame_type {
            if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
                if !aps.contains_key(bssid) || aps.get(bssid).unwrap().ssid == "<hidden>" {
                    let ap = aps.entry(bssid.clone()).or_insert_with(|| AccessPoint {
                        bssid: bssid.clone(),
                        ssid: ssid.clone(),
                        rssi: frame.rssi,
                        channel: frame.channel,
                        last_seen: frame.timestamp,
                        beacon_count: 0,
                        security: frame.security.clone(),
                    });
                    
                    if let Some(rssi) = frame.rssi {
                        ap.rssi = Some(rssi);
                    }
                    ap.last_seen = frame.timestamp;
                    if ap.ssid == "<hidden>" && ssid != "<hidden>" {
                        ap.ssid = ssid.clone();
                        println!("Discovered hidden SSID: {} for AP: {}", ssid, bssid);
                    }
                }
            }
        }
        
        else if let FrameType::Management(ManagementSubtype::AssociationRequest) = &frame.frame_type {
            if let (Some(bssid), Some(ssid)) = (&frame.bssid, &frame.ssid) {
                if !aps.contains_key(bssid) || aps.get(bssid).unwrap().ssid == "<hidden>" {
                    println!("Discovered hidden SSID from Association: {} for AP: {}", ssid, bssid);
                    let ap = aps.entry(bssid.clone()).or_insert_with(|| AccessPoint {
                        bssid: bssid.clone(),
                        ssid: ssid.clone(),
                        rssi: frame.rssi,
                        channel: frame.channel,
                        last_seen: frame.timestamp,
                        beacon_count: 0,
                        security: frame.security.clone(),
                    });
                    
                    if let Some(rssi) = frame.rssi {
                        ap.rssi = Some(rssi);
                    }
                    ap.last_seen = frame.timestamp;
                    if ap.security.is_none() {
                        ap.security = frame.security.clone();
                    }
                }
            }
        }
    }
    
    aps
}

fn channel_to_frequency(channel: u8) -> u16 {
    if channel >= 1 && channel <= 11 {
        2407 + (channel as u16) * 5
    } else if channel >= 36 && channel <= 165 {
        5150 + ((channel - 36) as u16) * 5
    } else {
        0 
    }
}

fn extract_security_info(frame_data: &[u8]) -> Option<SecurityType> {
    if frame_data.len() < 36 {
        return None;
    }
    
    let mut pos = 24;
    let mut has_rsn = false;
    
    while pos + 2 < frame_data.len() {
        let tag_number = frame_data[pos];
        let tag_length = frame_data[pos + 1] as usize;
        
        if tag_number == 48 { 
            has_rsn = true;
            return Some(SecurityType::WPA2);
        } else if tag_number == 221 && tag_length >= 8 {  
            if pos + 6 < frame_data.len() && frame_data[pos+2] == 0x00 && 
               frame_data[pos+3] == 0x50 && frame_data[pos+4] == 0xF2 && 
               frame_data[pos+5] == 0x01 {
                return Some(SecurityType::WPA);
            }
        }
        
        pos += 2 + tag_length;
        if pos >= frame_data.len() {
            break;
        }
    }
    
    if frame_data.len() > 34 {
        let capability = (frame_data[34] as u16) | ((frame_data[35] as u16) << 8);
        if (capability & 0x0010) != 0 {  
            if !has_rsn {
                return Some(SecurityType::WEP);
            }
        } else {
            return Some(SecurityType::Open);
        }
    }
    
    Some(SecurityType::Unknown)
}
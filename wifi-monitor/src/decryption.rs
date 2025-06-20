use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use pbkdf2::pbkdf2;
use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U8, U13},
    Ccm,
};
use crate::parser::{ParsedFrame, FrameType, ManagementSubtype};

type Aes128Ccm = Ccm<Aes128, U8, U13>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct EapolHandshake {
    pub bssid: String,
    pub client_mac: String,
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub replay_counter: u64,
    pub eapol_frame: Vec<u8>,
    pub msg_number: u8,
}

#[derive(Debug, Clone)]
pub struct DecryptionKeys {
    pub pmk: [u8; 32],      
    pub ptk: [u8; 64],    
    pub kck: [u8; 16],      
    pub kek: [u8; 16],      
    pub tk: [u8; 16],        
    pub rx_mic_key: [u8; 8],
    pub tx_mic_key: [u8; 8], 
    pub ssid: String,
    pub bssid: String,
    pub client_mac: String,
}

pub struct Decryptor {
    pub network_keys: HashMap<String, String>, 
    pub handshakes: HashMap<String, Vec<EapolHandshake>>,
    pub decryption_keys: HashMap<String, DecryptionKeys>, 
}

impl Decryptor {
    pub fn new() -> Self {
        Decryptor {
            network_keys: HashMap::new(),
            handshakes: HashMap::new(),
            decryption_keys: HashMap::new(),
        }
    }

    pub fn add_network(&mut self, ssid: &str, password: &str) {
        self.network_keys.insert(ssid.to_string(), password.to_string());
        println!("Added network '{}' for decryption", ssid);
    }

    pub fn process_packet(&mut self, frame: &ParsedFrame, ssid_map: &HashMap<String, String>) -> Option<Vec<u8>> {
        if let Some(payload) = &frame.payload {
            if self.is_eapol_frame(payload) {
                if let (Some(bssid), Some(client_mac)) = (&frame.bssid, &frame.mac_src) {
                    if let Some(handshake_info) = self.extract_handshake_info(bssid, client_mac, payload) {
                        self.add_handshake(handshake_info);
                        
                        if self.can_derive_keys(bssid) {
                            if let Some(ssid) = ssid_map.get(bssid) {
                                if let Some(password) = self.network_keys.get(ssid) {
                                    match self.derive_keys(bssid, ssid, password) {
                                        Ok(keys) => {
                                            println!("Successfully derived keys for network: {}", ssid);
                                            self.decryption_keys.insert(bssid.clone(), keys);
                                        }
                                        Err(e) => {
                                            println!("Failed to derive keys: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return None; 
            }
            
            if let FrameType::Data(_) = &frame.frame_type {
                if let Some(bssid) = &frame.bssid {
                    if let Some(keys) = self.decryption_keys.get(bssid) {
                        return self.decrypt_data_frame(frame, keys);
                    }
                }
            }
        }
        
        None
    }

    // EAPOL frame management
    fn is_eapol_frame(&self, payload: &[u8]) -> bool {
        payload.len() > 4 && payload[0] == 0xAA && payload[1] == 0xAA && 
        payload[2] == 0x03 && payload[3] == 0x00 && 
        payload[6] == 0x88 && payload[7] == 0x8E
    }

    fn extract_handshake_info(&self, bssid: &str, client_mac: &str, payload: &[u8]) -> Option<EapolHandshake> {
        if payload.len() < 99 {
            return None;
        }

        let eapol_start = 8;
        
        if payload[eapol_start] != 0x01 || payload[eapol_start+1] != 0x03 {
            return None;
        }
        
        let key_info = ((payload[eapol_start+5] as u16) << 8) | (payload[eapol_start+6] as u16);
        let mut replay_counter = 0u64;
        for i in 0..8 {
            replay_counter = (replay_counter << 8) | (payload[eapol_start+9+i] as u64);
        }
        
        let msg_number = if (key_info & 0x0008) == 0 {
            if (key_info & 0x0100) != 0 && (key_info & 0x0040) == 0 {
                1 
            } else if (key_info & 0x0100) != 0 && (key_info & 0x0040) != 0 {
                3 
            } else {
                0 
            }
        } else {
            if (key_info & 0x0100) != 0 && (key_info & 0x0040) != 0 {
                2 
            } else if (key_info & 0x0100) == 0 && (key_info & 0x0040) != 0 {
                4 
            } else {
                0 
            }
        };
        
        if msg_number == 0 {
            return None;
        }
        
        let nonce_offset = eapol_start + 17;
        let mut nonce = [0u8; 32];
        if nonce_offset + 32 <= payload.len() {
            nonce.copy_from_slice(&payload[nonce_offset..nonce_offset+32]);
        } else {
            return None;
        }
        
        let (anonce, snonce) = if msg_number == 1 || msg_number == 3 {
            (nonce, [0u8; 32]) 
        } else {
            ([0u8; 32], nonce) 
        };
        
        Some(EapolHandshake {
            bssid: bssid.to_string(),
            client_mac: client_mac.to_string(),
            anonce,
            snonce,
            replay_counter,
            eapol_frame: payload.to_vec(),
            msg_number,
        })
    }

    fn add_handshake(&mut self, handshake: EapolHandshake) {
        let handshakes = self.handshakes
            .entry(handshake.bssid.clone())
            .or_insert_with(Vec::new);
        
        let exists = handshakes.iter().any(|h| h.msg_number == handshake.msg_number);
        if !exists {
            println!("📦 Captured handshake message {} for {}", handshake.msg_number, handshake.bssid);
            handshakes.push(handshake);
        }
    }

    fn can_derive_keys(&self, bssid: &str) -> bool {
        if let Some(handshakes) = self.handshakes.get(bssid) {
            let has_msg1 = handshakes.iter().any(|h| h.msg_number == 1);
            let has_msg2 = handshakes.iter().any(|h| h.msg_number == 2);
            
            has_msg1 && has_msg2
        } else {
            false
        }
    }

    fn derive_keys(&self, bssid: &str, ssid: &str, password: &str) -> Result<DecryptionKeys, String> {
        let handshakes = match self.handshakes.get(bssid) {
            Some(h) => h,
            None => return Err("No handshakes available".to_string()),
        };
        
        let msg1 = handshakes.iter().find(|h| h.msg_number == 1)
            .ok_or("Message 1 not found")?;
        let msg2 = handshakes.iter().find(|h| h.msg_number == 2)
            .ok_or("Message 2 not found")?;
        
        let mut pmk = [0u8; 32];
        pbkdf2::<HmacSha1>(
            password.as_bytes(),
            ssid.as_bytes(),
            4096,
            &mut pmk
        );
        
        let mut ptk = [0u8; 64];
        
        let bssid_bytes = self.mac_addr_to_bytes(bssid)
            .ok_or("Invalid BSSID format")?;
        let client_mac_bytes = self.mac_addr_to_bytes(&msg2.client_mac)
            .ok_or("Invalid client MAC format")?;
        
        self.prf_512(
            &pmk,
            b"Pairwise key expansion",
            &bssid_bytes,
            &client_mac_bytes,
            &msg1.anonce,
            &msg2.snonce,
            &mut ptk
        );
        
        let mut kck = [0u8; 16];
        let mut kek = [0u8; 16];
        let mut tk = [0u8; 16];
        let mut rx_mic_key = [0u8; 8];
        let mut tx_mic_key = [0u8; 8];
        
        kck.copy_from_slice(&ptk[0..16]);    
        kek.copy_from_slice(&ptk[16..32]);   
        tk.copy_from_slice(&ptk[32..48]);    
        rx_mic_key.copy_from_slice(&ptk[48..56]); 
        tx_mic_key.copy_from_slice(&ptk[56..64]);
        
        Ok(DecryptionKeys {
            pmk,
            ptk,
            kck,
            kek,
            tk,
            rx_mic_key,
            tx_mic_key,
            ssid: ssid.to_string(),
            bssid: bssid.to_string(),
            client_mac: msg2.client_mac.clone(),
        })
    }

    fn prf_512(&self, key: &[u8], prefix: &[u8], mac1: &[u8], mac2: &[u8], 
               nonce1: &[u8], nonce2: &[u8], output: &mut [u8; 64]) {
        let (mac_a, mac_b) = if mac1 < mac2 {
            (mac1, mac2)
        } else {
            (mac2, mac1)
        };
        
        let (nonce_a, nonce_b) = if nonce1 < nonce2 {
            (nonce1, nonce2)
        } else {
            (nonce2, nonce1)
        };
        
        let mut data = Vec::with_capacity(prefix.len() + mac_a.len() + mac_b.len() + nonce_a.len() + nonce_b.len() + 1);
        data.extend_from_slice(prefix);
        data.push(0); 
        data.extend_from_slice(mac_a);
        data.extend_from_slice(mac_b);
        data.extend_from_slice(nonce_a);
        data.extend_from_slice(nonce_b);
        
        for i in 0..4 {
            let mut data_with_counter = data.clone();
            data_with_counter.push(i as u8);
            
            let mut hmac = HmacSha1::new_from_slice(key)
                .expect("HMAC initialization should not fail");
            hmac.update(&data_with_counter);
            let result = hmac.finalize().into_bytes();
            
            let offset = i * 16;
            for j in 0..16 {
                if offset + j < 64 {
                    output[offset + j] = result[j];
                }
            }
        }
    }

    fn mac_addr_to_bytes(&self, mac: &str) -> Option<[u8; 6]> {
        let mut bytes = [0u8; 6];
        let parts: Vec<&str> = mac.split(':').collect();
        
        if parts.len() != 6 {
            return None;
        }
        
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }
        
        Some(bytes)
    }

    // Data frame decryption
    fn decrypt_data_frame(&self, frame: &ParsedFrame, keys: &DecryptionKeys) -> Option<Vec<u8>> {
        if let Some(payload) = &frame.payload {
            if payload.len() < 16 {
                return None;
            }
            
            let pn = [
                payload[7], payload[6], payload[5], payload[4], payload[1], payload[0]
            ];
            
            let encrypted_data = &payload[8..payload.len()-8]; 
            let mic = &payload[payload.len()-8..];
            
            // Construct the nonce (13 bytes)
            let mut nonce = [0u8; 13];
            nonce[0] = 0; 
            
            let client_mac_bytes = match self.mac_addr_to_bytes(&keys.client_mac) {
                Some(mac) => mac,
                None => return None,
            };
            
            let bssid_bytes = match self.mac_addr_to_bytes(&keys.bssid) {
                Some(mac) => mac,
                None => return None,
            };
            
            let from_ap = frame.mac_src == keys.bssid;
            
            if from_ap {
                nonce[1..7].copy_from_slice(&bssid_bytes);
            } else {
                nonce[1..7].copy_from_slice(&client_mac_bytes);
            }
            
            nonce[7..13].copy_from_slice(&pn);

            let is_qos_data = match &frame.frame_type {
                FrameType::Data(subtype) => {
                    matches!(subtype, parser::DataSubtype::QoSData)
                },
                _ => false,
            };
            
            // Get MAC addresses for AAD
            let addr1_bytes = match self.mac_addr_to_bytes(&frame.mac_dst) {
                Some(mac) => mac,
                None => return None,
            };
            
            let addr2_bytes = match self.mac_addr_to_bytes(&frame.mac_src) {
                Some(mac) => mac,
                None => return None,
            };
            
            let addr3_bytes = match &frame.bssid {
                Some(bssid) => match self.mac_addr_to_bytes(bssid) {
                    Some(mac) => mac,
                    None => return None,
                },
                None => return None,
            };
            
            let frame_type_value = match &frame.frame_type {
                FrameType::Data(_) => 0x08, 
                _ => 0x08, 
            };
            
            // Masked frame control field 
            let frame_control = [
                frame_type_value, 
                0x01,            
            ];
            
            let sequence_number = frame.sequence_number.unwrap_or(0);
            let sequence_control = [
                ((sequence_number >> 4) & 0xFF) as u8,
                ((sequence_number & 0xF0) >> 4) as u8, 
            ];
            
            let mut aad = Vec::new();
            
            aad.extend_from_slice(&frame_control);
            
            aad.extend_from_slice(&addr1_bytes);
            aad.extend_from_slice(&addr2_bytes);
            aad.extend_from_slice(&addr3_bytes);
            
            aad.extend_from_slice(&sequence_control);
        
            if is_qos_data {
                let qos_control = [0x00, 0x00]; 
                aad.extend_from_slice(&qos_control);
            }
            
            println!("AAD length: {} bytes, is_qos: {}", aad.len(), is_qos_data);
            
            // Try to decrypt
            let mut tag = [0u8; 8]; 
            tag.copy_from_slice(mic);
            
            let mut decrypted = encrypted_data.to_vec();
            
            let cipher = match Aes128Ccm::new_from_slice(&keys.tk) {
                Ok(c) => c,
                Err(_) => return None,
            };
            
            match cipher.decrypt_in_place_detached(
                &nonce.into(),
                &aad,
                &mut decrypted,
                &tag.into()
            ) {
                Ok(_) => {
                    println!("Successfully decrypted packet!");
                    Some(decrypted)
                },
                Err(e) => {
                    println!("Decryption failed: {:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }
}
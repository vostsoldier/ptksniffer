use std::io::{self, Write};

pub fn display_results(mac: &str, ssid: &str, rssi: i32) {
    let output = format!("MAC: {}, SSID: {}, RSSI: {}", mac, ssid, rssi);
    println!("{}", output);
}

pub fn log_to_file(mac: &str, ssid: &str, rssi: i32) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("capture_log.txt")?;
    writeln!(file, "MAC: {}, SSID: {}, RSSI: {}", mac, ssid, rssi)?;
    Ok(())
}

pub fn display_error(message: &str) {
    eprintln!("Error: {}", message);
}
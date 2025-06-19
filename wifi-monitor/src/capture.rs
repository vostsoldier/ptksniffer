use std::process::Command;
use std::io::{self, Write};

pub fn set_monitor_mode(interface: &str) -> io::Result<()> {
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("down")
        .output()?;

    // Set the interface into monitor mode
    Command::new("sudo")
        .arg("iw")
        .arg(interface)
        .arg("set")
        .arg("type")
        .arg("monitor")
        .output()?;

    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("up")
        .output()?;

    Ok(())
}

pub fn capture_frames(interface: &str) -> io::Result<()> {
    let output = Command::new("sudo")
        .arg("tcpdump")
        .arg("-i")
        .arg(interface)
        .arg("-e")
        .arg("-s")
        .arg("0")
        .arg("type")
        .arg("mgt")
        .arg("or")
        .arg("type")
        .arg("data")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() {
        eprintln!("Error capturing frames: {}", stderr);
    }

    println!("{}", stdout);

    Ok(())
}
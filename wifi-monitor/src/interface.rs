use std::process::Command;

pub struct WifiInterface {
    interface_name: String,
}

impl WifiInterface {
    pub fn new(interface_name: &str) -> Self {
        WifiInterface {
            interface_name: interface_name.to_string(),
        }
    }

    pub fn set_monitor_mode(&self) -> Result<(), String> {
        Command::new("sudo")
            .arg("ifconfig")
            .arg(&self.interface_name)
            .arg("down")
            .output()
            .map_err(|e| e.to_string())?;

        // Set monitor mode
        Command::new("sudo")
            .arg("iw")
            .arg(&self.interface_name)
            .arg("set")
            .arg("type")
            .arg("monitor")
            .output()
            .map_err(|e| e.to_string())?;

        Command::new("sudo")
            .arg("ifconfig")
            .arg(&self.interface_name)
            .arg("up")
            .output()
            .map_err(|e| e.to_string())?;

        if !self.is_monitor_mode()? {
            return Err(format!("Failed to set {} to monitor mode", self.interface_name));
        }

        Ok(())
    }

    pub fn get_interface_name(&self) -> &str {
        &self.interface_name
    }

    pub fn is_monitor_mode(&self) -> Result<bool, String> {
        let output = Command::new("sudo")
            .arg("iw")
            .arg(&self.interface_name)
            .arg("info")
            .output()
            .map_err(|e| format!("Failed to execute iw command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        
        Ok(output_str.contains("type monitor"))
    }
    
    pub fn set_managed_mode(&self) -> Result<(), String> {
        Command::new("sudo")
            .arg("ifconfig")
            .arg(&self.interface_name)
            .arg("down")
            .output()
            .map_err(|e| e.to_string())?;

        // Set managed mode
        Command::new("sudo")
            .arg("iw")
            .arg(&self.interface_name)
            .arg("set")
            .arg("type")
            .arg("managed")
            .output()
            .map_err(|e| e.to_string())?;

        Command::new("sudo")
            .arg("ifconfig")
            .arg(&self.interface_name)
            .arg("up")
            .output()
            .map_err(|e| e.to_string())?;

        Ok(())
    }
    
    pub fn set_channel(&self, channel: u8) -> Result<(), String> {
        Command::new("sudo")
            .arg("iw")
            .arg(&self.interface_name)
            .arg("set")
            .arg("channel")
            .arg(channel.to_string())
            .output()
            .map_err(|e| format!("Failed to set channel: {}", e))?;
            
        Ok(())
    }

    fn execute_command_with_check(&self, cmd: &str, args: &[&str], error_msg: &str) -> Result<(), String> {
        let output = Command::new("sudo")
            .arg(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("{}: {}", error_msg, e))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("{}: {}", error_msg, stderr));
        }
        
        Ok(())
    }
}
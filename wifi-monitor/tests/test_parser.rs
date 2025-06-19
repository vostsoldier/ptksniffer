// unit tests for parsers cuz I'm too lazy to test the actual code with a raspberry pi

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let frame = /* example frame data */;
        let mac = parse_mac_address(frame);
        assert_eq!(mac, /* expected MAC address */);
    }

    #[test]
    fn test_parse_ssid() {
        let frame = /* example frame data */;
        let ssid = parse_ssid(frame);
        assert_eq!(ssid, /* expected SSID */);
    }

    #[test]
    fn test_parse_rssi() {
        let frame = /* example frame data */;
        let rssi = parse_rssi(frame);
        assert_eq!(rssi, /* expected RSSI value */);
    }

}
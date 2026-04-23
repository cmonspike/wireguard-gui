use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct WgDumpInterface {
    pub name: String,
    pub private_key: Option<String>,
    pub listen_port: u16,
    pub fwmark: u32,
}

#[derive(Debug, Clone)]
pub struct WgDumpPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: String,
    pub latest_handshake: u64,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Error)]
pub enum ParseDumpError {
    #[error("empty dump")]
    Empty,
    #[error("invalid line: {0}")]
    BadLine(String),
}

/// Parses `wg show all dump` output.
///
/// Supports the legacy layout (3-column interface lines, 8-column peers) and newer
/// `wireguard-tools` output that prefixes each line with the interface name (5 and 9 columns).
/// For legacy dumps, pass the same ordered list as `wg show interfaces`.
pub fn parse_wg_show_dump(
    dump: &str,
    interface_names_in_order: &[String],
) -> Result<Vec<(WgDumpInterface, Vec<WgDumpPeer>)>, ParseDumpError> {
    let mut blocks: Vec<(WgDumpInterface, Vec<WgDumpPeer>)> = Vec::new();
    let mut current: Option<(WgDumpInterface, Vec<WgDumpPeer>)> = None;
    let mut iface_index = 0usize;

    for line in dump.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() == 3 {
            // interface line: private_key, listen_port, fwmark
            if let Some(t) = current.take() {
                blocks.push(t);
            }
            let name = interface_names_in_order
                .get(iface_index)
                .cloned()
                .unwrap_or_else(|| format!("unknown{iface_index}"))
                .to_string();
            iface_index += 1;
            let privk = if cols[0].is_empty() {
                None
            } else {
                Some(cols[0].to_string())
            };
            let listen_port: u16 = cols[1].parse().unwrap_or(0);
            let fwmark: u32 = parse_fwmark(cols[2]);
            let iface = WgDumpInterface {
                name,
                private_key: privk,
                listen_port,
                fwmark,
            };
            current = Some((iface, Vec::new()));
        } else if cols.len() == 5 {
            // `wg show all dump` (newer wireguard-tools): ifname, private, public, listen_port, fwmark
            if let Some(t) = current.take() {
                blocks.push(t);
            }
            let name = cols[0].to_string();
            iface_index += 1;
            let privk = if cols[1].is_empty() {
                None
            } else {
                Some(cols[1].to_string())
            };
            let listen_port: u16 = cols[3].parse().unwrap_or(0);
            let fwmark: u32 = parse_fwmark(cols[4]);
            let iface = WgDumpInterface {
                name,
                private_key: privk,
                listen_port,
                fwmark,
            };
            current = Some((iface, Vec::new()));
        } else if cols.len() == 8 {
            let peer = WgDumpPeer {
                public_key: cols[0].to_string(),
                preshared_key: if cols[1].is_empty() {
                    None
                } else {
                    Some(cols[1].to_string())
                },
                endpoint: if cols[2].contains("(none)") || cols[2].is_empty() {
                    None
                } else {
                    Some(cols[2].to_string())
                },
                allowed_ips: cols[3].to_string(),
                latest_handshake: cols[4].parse().unwrap_or(0),
                transfer_rx: cols[5].parse().unwrap_or(0),
                transfer_tx: cols[6].parse().unwrap_or(0),
                persistent_keepalive: parse_keepalive(cols[7]),
            };
            let Some(ref mut cur) = current else {
                return Err(ParseDumpError::BadLine(line.into()));
            };
            cur.1.push(peer);
        } else if cols.len() == 9 {
            // `wg show all dump` (newer): ifname, then same 8 peer columns as legacy.
            let ifname = cols[0];
            let peer = WgDumpPeer {
                public_key: cols[1].to_string(),
                preshared_key: if cols[2].is_empty() {
                    None
                } else {
                    Some(cols[2].to_string())
                },
                endpoint: if cols[3].contains("(none)") || cols[3].is_empty() {
                    None
                } else {
                    Some(cols[3].to_string())
                },
                allowed_ips: cols[4].to_string(),
                latest_handshake: cols[5].parse().unwrap_or(0),
                transfer_rx: cols[6].parse().unwrap_or(0),
                transfer_tx: cols[7].parse().unwrap_or(0),
                persistent_keepalive: parse_keepalive(cols[8]),
            };
            let Some(ref mut cur) = current else {
                return Err(ParseDumpError::BadLine(line.into()));
            };
            if cur.0.name != ifname {
                return Err(ParseDumpError::BadLine(line.into()));
            }
            cur.1.push(peer);
        } else {
            return Err(ParseDumpError::BadLine(line.into()));
        }
    }
    if let Some(t) = current {
        blocks.push(t);
    }
    Ok(blocks)
}

fn parse_fwmark(s: &str) -> u32 {
    let s = s.trim();
    if s.eq_ignore_ascii_case("off") {
        return 0;
    }
    u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| s.parse().unwrap_or(0))
}

fn parse_keepalive(s: &str) -> u16 {
    let s = s.trim();
    if s.eq_ignore_ascii_case("off") || s.is_empty() {
        return 0;
    }
    s.parse().unwrap_or(0)
}

/// Parses `wg show <iface> dump` — single interface, first line is interface.
pub fn parse_wg_show_iface_dump(
    iface: &str,
    dump: &str,
) -> Result<(WgDumpInterface, Vec<WgDumpPeer>), ParseDumpError> {
    let v = parse_wg_show_dump(dump, &[iface.to_string()])?;
    v.into_iter().next().ok_or(ParseDumpError::Empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_field_interface_and_peer() {
        let dump = "YF7c1g==\t51820\t0\n\
                    peerpubkey\t\t(none)\t10.0.0.0/24\t0\t0\t0\t0\n";
        let blocks = parse_wg_show_dump(dump, &["wg0".into()]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0.name, "wg0");
        assert_eq!(blocks[0].0.listen_port, 51820);
        assert_eq!(blocks[0].1.len(), 1);
        assert_eq!(blocks[0].1[0].public_key, "peerpubkey");
    }

    #[test]
    fn parses_wg_show_all_dump_with_ifname_prefix() {
        let dump = "wg0\tprivk\tpubk\t56080\t0xca6c\n\
                    wg0\tpeerpub\tpsk\t155.1.2.3:51820\t0.0.0.0/0\t0\t0\t0\toff\n";
        let blocks = parse_wg_show_dump(dump, &["wg0".into()]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0.name, "wg0");
        assert_eq!(blocks[0].0.listen_port, 56080);
        assert_eq!(blocks[0].0.fwmark, 0xca6c);
        assert_eq!(blocks[0].1.len(), 1);
        assert_eq!(blocks[0].1[0].public_key, "peerpub");
        assert_eq!(blocks[0].1[0].endpoint.as_deref(), Some("155.1.2.3:51820"));
    }
}

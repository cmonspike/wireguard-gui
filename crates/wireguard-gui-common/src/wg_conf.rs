use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct WgQuickConf {
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub private_key: Option<String>,
    pub peers: Vec<WgQuickPeer>,
}

#[derive(Debug, Clone, Default)]
pub struct WgQuickPeer {
    pub public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub allowed_ips: Option<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Error)]
pub enum ParseConfError {
    #[error("invalid config: {0}")]
    Invalid(&'static str),
}

/// Minimal `[Interface]` / `[Peer]` parser for wg-quick style files.
pub fn parse_wg_quick_conf(text: &str) -> Result<WgQuickConf, ParseConfError> {
    let mut conf = WgQuickConf::default();
    let mut section: Option<&str> = None;
    let mut peer = WgQuickPeer::default();

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if section == Some("Peer") {
                conf.peers.push(std::mem::take(&mut peer));
            }
            section = Some(&line[1..line.len() - 1]);
            continue;
        }
        let Some((k, v)) = line.split_once('=').map(|(a, b)| (a.trim(), b.trim())) else {
            continue;
        };
        match section {
            Some("Interface") => match k {
                "Address" => {
                    for p in v.split(',') {
                        let s = p.trim();
                        if !s.is_empty() {
                            conf.address.push(s.to_string());
                        }
                    }
                }
                "DNS" => {
                    for p in v.split(',') {
                        let s = p.trim();
                        if !s.is_empty() {
                            conf.dns.push(s.to_string());
                        }
                    }
                }
                "ListenPort" => {
                    conf.listen_port = v.parse().ok();
                }
                "PrivateKey" => conf.private_key = Some(v.to_string()),
                _ => {}
            },
            Some("Peer") => match k {
                "PublicKey" => peer.public_key = Some(v.to_string()),
                "PresharedKey" => peer.preshared_key = Some(v.to_string()),
                "AllowedIPs" => peer.allowed_ips = Some(v.to_string()),
                "Endpoint" => peer.endpoint = Some(v.to_string()),
                "PersistentKeepalive" => peer.persistent_keepalive = v.parse().ok(),
                _ => {}
            },
            _ => {}
        }
    }
    if section == Some("Peer") {
        conf.peers.push(peer);
    }
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sample() {
        let s = r#"
[Interface]
PrivateKey = abc
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = peerpub
AllowedIPs = 0.0.0.0/0
Endpoint = x:51820
"#;
        let c = parse_wg_quick_conf(s).unwrap();
        assert_eq!(c.address, vec!["10.0.0.2/32"]);
        assert_eq!(c.dns, vec!["1.1.1.1"]);
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.peers[0].public_key.as_deref(), Some("peerpub"));
    }
}

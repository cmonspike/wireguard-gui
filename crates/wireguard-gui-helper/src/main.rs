//! Privileged helper — install setcap is NOT used; run via `pkexec` from the GUI.

use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use wireguard_gui_common::{
    parse_wg_quick_conf, parse_wg_show_dump, validate_tunnel_name, CreateTunnelRequest,
    HelperErrorResponse, PeerStatus, SimpleOkResponse, StatusResponse, TunnelStatus,
};

const WG_DIR: &str = "/etc/wireguard";
const POLKIT_RULE_PATH: &str = "/etc/polkit-1/rules.d/30-wireguard-gui.rules";

#[derive(Parser)]
#[command(name = "wireguard-gui-helper")]
#[command(about = "Privileged operations for WireGuard GUI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Emit JSON status for all tunnels (configs + live wg state).
    Status,
    /// `wg-quick up <name>` using `/etc/wireguard/<name>.conf`.
    Up { name: String },
    /// `wg-quick down <name>`.
    Down { name: String },
    /// Bring tunnel down if up, then remove `/etc/wireguard/<name>.conf`.
    Delete { name: String },
    /// Read [`CreateTunnelRequest`] JSON from `--file` (used by the GUI; `pkexec` does not reliably forward stdin).
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    /// Copy an existing `.conf` into `/etc/wireguard/` (basename from `--name` or file stem).
    Import {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Read `/etc/wireguard/<name>.conf` contents.
    Read { name: String },
    /// Validate and overwrite `/etc/wireguard/<name>.conf` from `--file`.
    Update {
        name: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Install/update scoped Polkit rule for fewer repeated authentication prompts.
    InstallPolkitRule,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Status => cmd_status(),
        Commands::Up { name } => cmd_up(&name),
        Commands::Down { name } => cmd_down(&name),
        Commands::Delete { name } => cmd_delete(&name),
        Commands::Create { file } => cmd_create(&file),
        Commands::Import { path, name } => cmd_import(&path, name.as_deref()),
        Commands::Read { name } => cmd_read(&name),
        Commands::Update { name, file } => cmd_update(&name, &file),
        Commands::InstallPolkitRule => cmd_install_polkit_rule(),
    };
    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Err(e) => {
            let err = HelperErrorResponse::new(e.message, e.details);
            println!("{}", serde_json::to_string_pretty(&err).unwrap());
            std::process::exit(1);
        }
    }
}

struct CmdErr {
    message: String,
    details: Option<String>,
}

impl CmdErr {
    fn new(message: impl Into<String>, details: Option<String>) -> Self {
        Self {
            message: message.into(),
            details,
        }
    }
}

fn run_capture(program: &str, args: &[&str]) -> Result<String, CmdErr> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| CmdErr::new(format!("failed to run {program}: {e}"), None))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(CmdErr::new(
            format!("{program} exited with {}", out.status),
            Some(if stderr.is_empty() {
                stdout.clone()
            } else {
                stderr
            }),
        ));
    }
    Ok(stdout)
}

fn wg_show_interfaces() -> Result<Vec<String>, CmdErr> {
    let s = run_capture("wg", &["show", "interfaces"])?;
    Ok(s.split_whitespace().map(|x| x.to_string()).collect())
}

fn wg_show_all_dump() -> Result<String, CmdErr> {
    run_capture("wg", &["show", "all", "dump"])
}

fn wg_quick(args: &[&str]) -> Result<(), CmdErr> {
    let out = Command::new("wg-quick")
        .args(args)
        .output()
        .map_err(|e| CmdErr::new(format!("failed to run wg-quick: {e}"), None))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        return Err(CmdErr::new(
            "wg-quick failed",
            Some(if stderr.is_empty() {
                stdout
            } else {
                stderr
            }),
        ));
    }
    Ok(())
}

fn wg_genkey() -> Result<String, CmdErr> {
    let out = Command::new("wg")
        .args(["genkey"])
        .output()
        .map_err(|e| CmdErr::new(format!("wg genkey: {e}"), None))?;
    if !out.status.success() {
        return Err(CmdErr::new("wg genkey failed", None));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn wg_pubkey(privkey: &str) -> Result<String, CmdErr> {
    let mut child = Command::new("wg")
        .args(["pubkey"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CmdErr::new(format!("wg pubkey: {e}"), None))?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(privkey.trim().as_bytes())
        .map_err(|e| CmdErr::new(format!("wg pubkey stdin: {e}"), None))?;
    let out = child
        .wait_with_output()
        .map_err(|e| CmdErr::new(format!("wg pubkey: {e}"), None))?;
    if !out.status.success() {
        return Err(CmdErr::new(
            "wg pubkey failed",
            Some(String::from_utf8_lossy(&out.stderr).to_string()),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn list_conf_basenames() -> Result<Vec<String>, CmdErr> {
    let rd =
        fs::read_dir(WG_DIR).map_err(|e| CmdErr::new(format!("cannot read {WG_DIR}: {e}"), None))?;
    let mut names = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("conf") {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn read_conf_text(name: &str) -> Result<String, CmdErr> {
    let p = Path::new(WG_DIR).join(format!("{name}.conf"));
    fs::read_to_string(&p).map_err(|e| CmdErr::new(format!("read {}: {e}", p.display()), None))
}

fn ip_wireguard_state() -> Result<BTreeMap<String, bool>, CmdErr> {
    let j = run_capture("ip", &["-j", "link", "show", "type", "wireguard"])?;
    let v: serde_json::Value =
        serde_json::from_str(&j).map_err(|e| CmdErr::new(format!("ip -j parse: {e}"), Some(j)))?;
    let mut m = BTreeMap::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            let name = item["ifname"].as_str().unwrap_or("").to_string();
            // WireGuard often reports operstate "UNKNOWN" while the link is usable; `ip` still
            // sets the IFF_UP flag. Treat UP like `ip link` / wg-quick: use the UP flag bit.
            let up = item["flags"]
                .as_array()
                .is_some_and(|flags| flags.iter().any(|v| v.as_str() == Some("UP")));
            if !name.is_empty() {
                m.insert(name, up);
            }
        }
    }
    Ok(m)
}

fn ip_addresses(ifname: &str) -> Result<Vec<String>, CmdErr> {
    let j = run_capture("ip", &["-j", "addr", "show", "dev", ifname])?;
    let v: serde_json::Value = serde_json::from_str(&j)
        .map_err(|e| CmdErr::new(format!("ip addr -j parse: {e}"), Some(j.clone())))?;
    let mut addrs = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            if let Some(addr_info) = item["addr_info"].as_array() {
                for a in addr_info {
                    if let (Some(local), Some(prefix)) =
                        (a["local"].as_str(), a["prefixlen"].as_u64())
                    {
                        addrs.push(format!("{local}/{prefix}"));
                    }
                }
            }
        }
    }
    Ok(addrs)
}

fn cmd_status() -> Result<serde_json::Value, CmdErr> {
    let mut warnings = Vec::new();
    let conf_names = list_conf_basenames().unwrap_or_else(|e| {
        warnings.push(format!("listing configs: {}", e.message));
        Vec::new()
    });

    let wg_ifaces = wg_show_interfaces().unwrap_or_else(|e| {
        warnings.push(format!("wg show interfaces: {}", e.message));
        Vec::new()
    });

    let dump_raw = wg_show_all_dump().unwrap_or_else(|e| {
        warnings.push(format!("wg show all dump: {}", e.message));
        String::new()
    });

    let dump_blocks = parse_wg_show_dump(&dump_raw, &wg_ifaces).unwrap_or_else(|e| {
        warnings.push(format!("parse wg dump: {e}"));
        Vec::new()
    });

    let mut live_by_name: BTreeMap<String, wireguard_gui_common::WgDumpInterface> = BTreeMap::new();
    let mut live_peers_by_name: BTreeMap<String, Vec<wireguard_gui_common::WgDumpPeer>> =
        BTreeMap::new();
    for (iface, peers) in dump_blocks {
        let n = iface.name.clone();
        live_by_name.insert(n.clone(), iface);
        live_peers_by_name.insert(n, peers);
    }

    let link_state = ip_wireguard_state().unwrap_or_else(|e| {
        warnings.push(format!("ip link: {}", e.message));
        BTreeMap::new()
    });

    let mut names: BTreeSet<String> = conf_names.iter().cloned().collect();
    for n in &wg_ifaces {
        names.insert(n.clone());
    }

    let mut tunnels: Vec<TunnelStatus> = Vec::new();
    for name in names {
        let path = format!("{WG_DIR}/{}.conf", name);
        let has_config = Path::new(&path).is_file();
        let conf = if has_config {
            read_conf_text(&name).ok().and_then(|t| parse_wg_quick_conf(&t).ok())
        } else {
            None
        };

        let iface_up = link_state.get(&name).copied().unwrap_or(false);
        let mut addresses = if iface_up {
            ip_addresses(&name).unwrap_or_default()
        } else {
            Vec::new()
        };
        if addresses.is_empty() {
            if let Some(ref c) = conf {
                addresses = c.address.clone();
            }
        }

        let listen_port = if let Some(ref li) = live_by_name.get(&name) {
            if li.listen_port > 0 {
                Some(li.listen_port)
            } else {
                conf.as_ref().and_then(|c| c.listen_port)
            }
        } else {
            conf.as_ref().and_then(|c| c.listen_port)
        };

        let dns = conf.as_ref().map(|c| c.dns.clone()).unwrap_or_default();

        let mut peers: Vec<PeerStatus> = Vec::new();
        if let Some(ref c) = conf {
            for p in &c.peers {
                let pk = p.public_key.clone().unwrap_or_default();
                if pk.is_empty() {
                    continue;
                }
                peers.push(PeerStatus {
                    public_key: pk,
                    endpoint: p.endpoint.clone(),
                    allowed_ips: p
                        .allowed_ips
                        .clone()
                        .unwrap_or_else(|| "(none)".to_string()),
                    latest_handshake: None,
                    transfer_rx: 0,
                    transfer_tx: 0,
                    persistent_keepalive: p.persistent_keepalive,
                });
            }
        }

        if iface_up {
            if let Some(live) = live_peers_by_name.get(&name) {
                peers = live
                    .iter()
                    .map(|lp| PeerStatus {
                        public_key: lp.public_key.clone(),
                        endpoint: lp.endpoint.clone(),
                        allowed_ips: lp.allowed_ips.clone(),
                        latest_handshake: if lp.latest_handshake > 0 {
                            Some(lp.latest_handshake)
                        } else {
                            None
                        },
                        transfer_rx: lp.transfer_rx,
                        transfer_tx: lp.transfer_tx,
                        persistent_keepalive: if lp.persistent_keepalive > 0 {
                            Some(lp.persistent_keepalive)
                        } else {
                            None
                        },
                    })
                    .collect();
            }
        }

        tunnels.push(TunnelStatus {
            name: name.clone(),
            config_path: path,
            has_config_file: has_config,
            interface_up: iface_up,
            addresses,
            listen_port,
            dns,
            peers,
        });
    }

    tunnels.sort_by(|a, b| a.name.cmp(&b.name));

    if wg_ifaces.len() != live_by_name.len() && !wg_ifaces.is_empty() {
        warnings.push(format!(
            "wg interface count ({}) does not match parsed dump blocks ({}); names may be misaligned",
            wg_ifaces.len(),
            live_by_name.len()
        ));
    }

    let resp = StatusResponse { tunnels, warnings };
    Ok(serde_json::to_value(resp).unwrap())
}

fn cmd_up(name: &str) -> Result<serde_json::Value, CmdErr> {
    validate_tunnel_name(name).map_err(|m| CmdErr::new(m, None))?;
    let conf = Path::new(WG_DIR).join(format!("{name}.conf"));
    if !conf.is_file() {
        return Err(CmdErr::new(
            format!("missing config {}", conf.display()),
            None,
        ));
    }
    let conf_arg = conf.to_str().unwrap();
    // `wg-quick up` fails with "already exists" if a netdevice with this name is still
    // present (crash, partial teardown, `ip link set … down`, etc.). Status only treats
    // operstate UP as connected, so the GUI can show "Connect" while the device remains.
    let live = wg_show_interfaces().unwrap_or_default();
    if live.iter().any(|iface| iface == name) {
        let _ = wg_quick(&["down", conf_arg]);
    }
    wg_quick(&["up", conf_arg])?;
    // Same JSON as `status` so the GUI can refresh in one pkexec (no second prompt).
    cmd_status()
}

fn cmd_down(name: &str) -> Result<serde_json::Value, CmdErr> {
    validate_tunnel_name(name).map_err(|m| CmdErr::new(m, None))?;
    let conf = Path::new(WG_DIR).join(format!("{name}.conf"));
    if !conf.is_file() {
        return Err(CmdErr::new(
            format!("missing config {}", conf.display()),
            None,
        ));
    }
    wg_quick(&["down", conf.to_str().unwrap()])?;
    cmd_status()
}

fn cmd_delete(name: &str) -> Result<serde_json::Value, CmdErr> {
    validate_tunnel_name(name).map_err(|m| CmdErr::new(m, None))?;
    let conf = Path::new(WG_DIR).join(format!("{name}.conf"));
    if conf.is_file() {
        let _ = cmd_down(name);
        fs::remove_file(&conf)
            .map_err(|e| CmdErr::new(format!("remove {}: {e}", conf.display()), None))?;
    }
    cmd_status()
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), CmdErr> {
    path.parent().ok_or_else(|| CmdErr::new("bad path", None))?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("wg.conf");
    let tmp = path.with_file_name(format!(".{fname}.tmp.{}", std::process::id()));
    fs::write(&tmp, contents).map_err(|e| CmdErr::new(format!("write tmp: {e}"), None))?;
    fs::rename(&tmp, path).map_err(|e| CmdErr::new(format!("rename: {e}"), None))?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

use std::os::unix::fs::PermissionsExt;

fn render_wg_quick_conf(
    privkey: &str,
    addresses: &[String],
    dns: &[String],
    listen_port: Option<u16>,
    peer: &wireguard_gui_common::CreatePeerRequest,
) -> String {
    let mut s = String::from("[Interface]\n");
    s.push_str(&format!("PrivateKey = {privkey}\n"));
    if !addresses.is_empty() {
        s.push_str(&format!("Address = {}\n", addresses.join(", ")));
    }
    if !dns.is_empty() {
        s.push_str(&format!("DNS = {}\n", dns.join(", ")));
    }
    if let Some(p) = listen_port {
        s.push_str(&format!("ListenPort = {p}\n"));
    }
    s.push('\n');
    s.push_str("[Peer]\n");
    s.push_str(&format!("PublicKey = {}\n", peer.public_key.trim()));
    if let Some(ref e) = peer.endpoint {
        if !e.is_empty() {
            s.push_str(&format!("Endpoint = {e}\n"));
        }
    }
    s.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.trim()));
    if let Some(ref psk) = peer.preshared_key {
        if !psk.is_empty() {
            s.push_str(&format!("PresharedKey = {psk}\n"));
        }
    }
    if let Some(ka) = peer.persistent_keepalive {
        if ka > 0 {
            s.push_str(&format!("PersistentKeepalive = {ka}\n"));
        }
    }
    s
}

fn cmd_create(path: &Path) -> Result<serde_json::Value, CmdErr> {
    let buf = fs::read_to_string(path)
        .map_err(|e| CmdErr::new(format!("read {}: {e}", path.display()), None))?;
    let req: CreateTunnelRequest =
        serde_json::from_str(&buf).map_err(|e| CmdErr::new(format!("invalid JSON: {e}"), None))?;
    validate_tunnel_name(&req.name).map_err(|m| CmdErr::new(m, None))?;
    if req.addresses.is_empty() {
        return Err(CmdErr::new("at least one Address is required", None));
    }

    let privkey = if req.generate_keys {
        wg_genkey()?
    } else {
        req.private_key
            .clone()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CmdErr::new("private_key required when generate_keys is false", None))?
    };

    let _ = wg_pubkey(&privkey)?; // validate key

    let path = Path::new(WG_DIR).join(format!("{}.conf", req.name));
    if path.exists() {
        return Err(CmdErr::new(format!("{} already exists", path.display()), None));
    }

    let text = render_wg_quick_conf(
        privkey.trim(),
        &req.addresses,
        &req.dns,
        req.listen_port,
        &req.peer,
    );
    atomic_write(&path, &text)?;
    cmd_status()
}

fn cmd_import(src: &Path, name_override: Option<&str>) -> Result<serde_json::Value, CmdErr> {
    let text = fs::read_to_string(src)
        .map_err(|e| CmdErr::new(format!("read {}: {e}", src.display()), None))?;
    let _parsed =
        parse_wg_quick_conf(&text).map_err(|e| CmdErr::new(e.to_string(), None))?;

    let name = if let Some(n) = name_override {
        n.to_string()
    } else {
        src.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| CmdErr::new("could not derive tunnel name", None))?
            .to_string()
    };
    validate_tunnel_name(&name).map_err(|m| CmdErr::new(m, None))?;
    let dest = Path::new(WG_DIR).join(format!("{name}.conf"));
    if dest.exists() {
        return Err(CmdErr::new(format!("{} already exists", dest.display()), None));
    }
    atomic_write(&dest, &text)?;
    cmd_status()
}

#[derive(serde::Serialize)]
struct ReadTunnelConfigResponse {
    ok: bool,
    name: String,
    contents: String,
}

fn cmd_read(name: &str) -> Result<serde_json::Value, CmdErr> {
    validate_tunnel_name(name).map_err(|m| CmdErr::new(m, None))?;
    let conf = Path::new(WG_DIR).join(format!("{name}.conf"));
    if !conf.is_file() {
        return Err(CmdErr::new(
            format!("missing config {}", conf.display()),
            None,
        ));
    }
    let contents =
        fs::read_to_string(&conf).map_err(|e| CmdErr::new(format!("read {}: {e}", conf.display()), None))?;
    Ok(serde_json::to_value(ReadTunnelConfigResponse {
        ok: true,
        name: name.to_string(),
        contents,
    })
    .unwrap())
}

fn cmd_update(name: &str, file: &Path) -> Result<serde_json::Value, CmdErr> {
    validate_tunnel_name(name).map_err(|m| CmdErr::new(m, None))?;
    let conf = Path::new(WG_DIR).join(format!("{name}.conf"));
    if !conf.is_file() {
        return Err(CmdErr::new(
            format!("missing config {}", conf.display()),
            None,
        ));
    }
    let text =
        fs::read_to_string(file).map_err(|e| CmdErr::new(format!("read {}: {e}", file.display()), None))?;
    let _parsed =
        parse_wg_quick_conf(&text).map_err(|e| CmdErr::new(format!("invalid config: {e}"), None))?;
    atomic_write(&conf, &text)?;
    cmd_status()
}

fn cmd_install_polkit_rule() -> Result<serde_json::Value, CmdErr> {
    let mut helper_programs = vec!["/usr/libexec/wireguard-gui-helper".to_string()];
    if let Ok(exe) = std::env::current_exe() {
        helper_programs.push(exe.to_string_lossy().into_owned());
        if let Ok(canon) = fs::canonicalize(&exe) {
            helper_programs.push(canon.to_string_lossy().into_owned());
        }
    }
    helper_programs.sort();
    helper_programs.dedup();
    let rule_contents = render_polkit_rule(&helper_programs);

    let path = Path::new(POLKIT_RULE_PATH);
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == rule_contents {
            return Ok(serde_json::to_value(SimpleOkResponse {
                ok: true,
                message: Some("Polkit rule already installed".into()),
            })
            .unwrap());
        }
    }
    atomic_write(path, &rule_contents)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    Ok(serde_json::to_value(SimpleOkResponse {
        ok: true,
        message: Some(format!("Installed {}", path.display())),
    })
    .unwrap())
}

fn render_polkit_rule(helper_programs: &[String]) -> String {
    let mut rule = String::from(
        "// Reduce repeated auth prompts for the WireGuard GUI helper while keeping scope narrow.\n\
         // This file is managed by wireguard-gui-helper.\n\
         polkit.addRule(function (action, subject) {\n\
         \x20 if (action.id != \"org.freedesktop.policykit.exec\") {\n\
         \x20\x20 return polkit.Result.NOT_HANDLED;\n\
         \x20 }\n\
         \n\
         \x20 var helperPrograms = {\n",
    );
    for p in helper_programs {
        rule.push_str(&format!("    \"{}\": true,\n", js_escape(p)));
    }
    rule.push_str(
        "  };\n\
         \n\
         \x20 if (!helperPrograms[action.lookup(\"program\")]) {\n\
         \x20\x20 return polkit.Result.NOT_HANDLED;\n\
         \x20 }\n\
         \n\
         \x20 if (!subject.local || !subject.active) {\n\
         \x20\x20 return polkit.Result.NOT_HANDLED;\n\
         \x20 }\n\
         \n\
         \x20 return polkit.Result.AUTH_ADMIN_KEEP;\n\
         });\n",
    );
    rule
}

fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\"', "\\\"")
}

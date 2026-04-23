//! WireGuard GUI — manages `wg-quick` style tunnels under `/etc/wireguard` via a Polkit-gated helper.

use adw::prelude::*;
use adw::ToastPriority;
use gtk::gio;
use ksni::{menu::StandardItem, MenuItem};
use serde::Deserialize;
use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use wireguard_gui_common::{
    CreatePeerRequest, CreateTunnelRequest, HelperErrorResponse, StatusResponse, TunnelStatus,
};

const APP_ID: &str = "io.github.wireguard_gui";
const POLKIT_RULE_PATH: &str = "/etc/polkit-1/rules.d/30-wireguard-gui.rules";

#[derive(Clone, Copy)]
enum TrayEvent {
    ToggleWindow,
    Quit,
}

struct TrayState {
    tx: mpsc::Sender<TrayEvent>,
}

impl ksni::Tray for TrayState {
    fn id(&self) -> String {
        "io.github.wireguard_gui".into()
    }

    fn title(&self) -> String {
        "WireGuard GUI".into()
    }

    fn icon_name(&self) -> String {
        // Cinnamon/xapp is more reliable with a regular themed icon name.
        "network-vpn".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayEvent::ToggleWindow);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![StandardItem {
            label: "Quit".into(),
            activate: Box::new(|this: &mut Self| {
                let _ = this.tx.send(TrayEvent::Quit);
            }),
            ..Default::default()
        }
        .into()]
    }
}

fn resolve_helper() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("WIREGUARD_GUI_HELPER") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(format!(
            "WIREGUARD_GUI_HELPER is set but not a file: {}",
            pb.display()
        ));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or_else(|| "could not locate executable directory".to_string())?;
    let sidecar = dir.join("wireguard-gui-helper");
    if sidecar.is_file() {
        return Ok(sidecar);
    }
    let system = PathBuf::from("/usr/libexec/wireguard-gui-helper");
    if system.is_file() {
        return Ok(system);
    }
    Err(format!(
        "helper binary not found. Install wireguard-gui-helper or set WIREGUARD_GUI_HELPER.\nExpected next to {} or at {}",
        exe.display(),
        system.display()
    ))
}

fn run_privileged_helper(args: &[String]) -> Result<String, String> {
    let helper = resolve_helper()?;
    let out = Command::new("pkexec")
        .arg(&helper)
        .args(args)
        .output()
        .map_err(|e| format!("pkexec: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        if let Ok(err) = serde_json::from_str::<HelperErrorResponse>(&stdout) {
            if !err.ok {
                let mut m = err.message;
                if let Some(d) = err.details {
                    m.push_str("\n");
                    m.push_str(&d);
                }
                return Err(m);
            }
        }
        if !stdout.trim().is_empty() {
            return Err(if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n{stderr}")
            });
        }
        return Err(if stderr.is_empty() {
            format!("pkexec/helper failed ({})", out.status)
        } else {
            stderr
        });
    }
    Ok(stdout)
}

fn should_bootstrap_polkit_rule() -> bool {
    !std::path::Path::new(POLKIT_RULE_PATH).is_file()
}

fn parse_status_json(s: &str) -> Result<StatusResponse, String> {
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| format!("bad JSON: {e}"))?;
    if v.get("ok") == Some(&serde_json::json!(false)) {
        let err: HelperErrorResponse =
            serde_json::from_value(v).map_err(|e| format!("error object: {e}"))?;
        let mut m = err.message;
        if let Some(d) = err.details {
            m.push('\n');
            m.push_str(&d);
        }
        return Err(m);
    }
    serde_json::from_value(v).map_err(|e| format!("status parse: {e}"))
}

#[derive(Debug, Deserialize)]
struct ReadTunnelConfigResponse {
    ok: bool,
    name: String,
    contents: String,
}

fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    for unit in ["KiB", "MiB", "GiB", "TiB"] {
        v /= KB;
        if v < 1024.0 {
            return format!("{v:.1} {unit}");
        }
    }
    format!("{:.1} PiB", v / KB)
}

fn fmt_handshake(ts: Option<u64>) -> String {
    let Some(ts) = ts else {
        return "Never".into();
    };
    if ts == 0 {
        return "Never".into();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ago = now.saturating_sub(ts);
    if ago < 5 {
        return "just now".into();
    }
    if ago < 60 {
        return format!("{ago}s ago");
    }
    if ago < 3600 {
        return format!("{}m ago", ago / 60);
    }
    if ago < 86400 {
        return format!("{}h ago", ago / 3600);
    }
    format!("{}d ago", ago / 86400)
}

fn show_toast(overlay: &adw::ToastOverlay, text: impl Into<String>) {
    let t = adw::Toast::new(&text.into());
    t.set_priority(ToastPriority::High);
    overlay.add_toast(t);
}

fn install_tech_theme() {
    let Some(display) = gtk::gdk::Display::default() else {
        return;
    };
    let css = gtk::CssProvider::new();
    css.load_from_string(
        "
window.wg-root {
  background: #0b1020;
  color: #dbe6ff;
}

window.wg-root .wg-sidebar,
window.wg-root .wg-sidebar * {
  background: #203765;
  color: #f6f9ff;
}

window.wg-root .wg-card {
  background: rgba(20, 30, 54, 0.85);
}

window.wg-root .wg-sidebar {
  border-right: 1px solid #4f6faa;
}

window.wg-root .wg-sidebar-header,
window.wg-root .wg-sidebar-header * {
  background: #2a477d;
  color: #ffffff;
}

window.wg-root .wg-sidebar-header label {
  font-weight: 700;
}

window.wg-root .wg-sidebar-list {
  background: #203765;
}

window.wg-root .wg-sidebar row {
  background: transparent;
  border: none;
  outline: none;
  box-shadow: none;
  margin: 4px 6px;
}

window.wg-root .wg-sidebar .wg-tunnel-row {
  background: #243a67;
  border: none;
  outline: none;
  box-shadow: none;
  border-radius: 10px;
  color: #f7f9ff;
}

window.wg-root .wg-sidebar row:hover .wg-tunnel-row {
  background: #2f4a83;
}

window.wg-root .wg-sidebar row:selected .wg-tunnel-row {
  background: #3b60a9;
}

window.wg-root .wg-sidebar .wg-tunnel-current {
  background: #3f5f9e;
}

window.wg-root .wg-sidebar .wg-tunnel-current label,
window.wg-root .wg-sidebar .wg-tunnel-current .subtitle,
window.wg-root .wg-sidebar .wg-tunnel-current .dim-label {
  color: #ffe66d;
  font-weight: 700;
}

window.wg-root .wg-sidebar .wg-tunnel-row,
window.wg-root .wg-sidebar .wg-tunnel-row:selected,
window.wg-root .wg-sidebar .wg-tunnel-row:focus,
window.wg-root .wg-sidebar .wg-tunnel-row:focus-visible,
window.wg-root .wg-sidebar .wg-tunnel-row:focus-within {
  border: none;
  outline: none;
  box-shadow: none;
}

window.wg-root .wg-sidebar row label,
window.wg-root .wg-sidebar row .subtitle,
window.wg-root .wg-sidebar row .dim-label {
  color: #eaf1ff;
}

window.wg-root .wg-sidebar row:selected label,
window.wg-root .wg-sidebar row:selected .subtitle {
  color: #ffe66d;
}

window.wg-root .wg-state-up {
  color: #27e6a6;
}

window.wg-root .wg-state-down {
  color: #92a3c7;
}

window.wg-root button.wg-connect {
  background: #1c8fda;
  color: white;
}

window.wg-root button.wg-disconnect,
window.wg-root button.wg-delete {
  background: #ca3d71;
  color: white;
}

window.wg-root .wg-details-card {
  background: #1a2a4b;
  border: 1px solid #2f4573;
  border-radius: 14px;
  padding: 10px;
}

window.wg-root .wg-details-card .wg-info-row {
  background: transparent;
  border: none;
  outline: none;
  box-shadow: none;
}

window.wg-root .wg-details-card .wg-info-title {
  color: #ecf2ff;
  font-weight: 600;
}

window.wg-root .wg-details-card .wg-info-value {
  color: #b8c8ea;
}

window.wg-root .wg-details-card .wg-info-divider {
  background: #2b3f67;
  min-height: 1px;
}
        ",
    );
    gtk::style_context_add_provider_for_display(
        &display,
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn add_pref_row(parent: &gtk::Box, title: &str, body: &str) {
    let row = gtk::Box::new(gtk::Orientation::Vertical, 2);
    row.add_css_class("wg-info-row");
    row.set_margin_top(4);
    row.set_margin_bottom(4);
    row.set_margin_start(8);
    row.set_margin_end(8);

    let title_lbl = gtk::Label::new(Some(title));
    title_lbl.add_css_class("wg-info-title");
    title_lbl.set_halign(gtk::Align::Start);
    title_lbl.set_xalign(0.0);
    row.append(&title_lbl);

    let body_lbl = gtk::Label::new(Some(body));
    body_lbl.add_css_class("wg-info-value");
    body_lbl.set_halign(gtk::Align::Start);
    body_lbl.set_xalign(0.0);
    body_lbl.set_wrap(true);
    body_lbl.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    body_lbl.set_selectable(true);
    row.append(&body_lbl);

    parent.append(&row);
    let divider = gtk::Separator::new(gtk::Orientation::Horizontal);
    divider.add_css_class("wg-info-divider");
    parent.append(&divider);
}

fn add_attr_row(expander: &adw::ExpanderRow, title: &str, body: &str) {
    let r = adw::ActionRow::new();
    r.set_title(title);
    r.set_subtitle(body);
    r.set_subtitle_selectable(true);
    r.set_subtitle_lines(4);
    expander.add_row(&r);
}

fn build_peer_rows(parent: &gtk::Box, tunnel: &TunnelStatus) {
    while let Some(child) = parent.first_child() {
        parent.remove(&child);
    }
    if tunnel.peers.is_empty() {
        let l = gtk::Label::new(Some("No peers in configuration."));
        l.add_css_class("dim-label");
        l.set_halign(gtk::Align::Start);
        parent.append(&l);
        return;
    }
    let title = gtk::Label::new(Some("Peers"));
    title.add_css_class("title-4");
    title.set_halign(gtk::Align::Start);
    parent.append(&title);

    for p in &tunnel.peers {
        let short_key = if p.public_key.len() > 20 {
            format!(
                "{}…{}",
                &p.public_key[..8],
                &p.public_key[p.public_key.len().saturating_sub(6)..]
            )
        } else {
            p.public_key.clone()
        };
        let row = adw::ExpanderRow::new();
        row.set_title(&short_key);
        row.set_subtitle(&fmt_handshake(p.latest_handshake));

        let ep = p.endpoint.clone().unwrap_or_else(|| "—".into());
        add_attr_row(&row, "Public key", &p.public_key);
        add_attr_row(&row, "Endpoint", &ep);
        add_attr_row(&row, "Allowed IPs", &p.allowed_ips);
        add_attr_row(
            &row,
            "Transfer",
            &format!(
                "↓ {}  ↑ {}",
                fmt_bytes(p.transfer_rx),
                fmt_bytes(p.transfer_tx)
            ),
        );
        parent.append(&row);
    }
}

#[derive(Clone)]
struct App {
    tunnels: Rc<RefCell<Vec<TunnelStatus>>>,
    selected: Rc<RefCell<Option<String>>>,
    list: gtk::ListBox,
    detail_root: gtk::Box,
    stack: gtk::Stack,
    empty: adw::StatusPage,
    toast_overlay: adw::ToastOverlay,
    window: gtk::ApplicationWindow,
    refreshing: Rc<RefCell<bool>>,
}

impl App {
    fn spawn_privileged(
        &self,
        args: Vec<String>,
        on_done: impl Fn(Result<String, String>) + 'static,
    ) {
        let (tx, rx) = mpsc::channel::<Result<String, String>>();
        std::thread::spawn(move || {
            let r = run_privileged_helper(&args);
            let _ = tx.send(r);
        });
        glib::idle_add_local(move || match rx.try_recv() {
                Ok(res) => {
                    on_done(res);
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
        });
    }

    /// Updates the tunnel list and detail pane from a [`StatusResponse`].
    fn apply_status_response(&self, status: &StatusResponse) {
        *self.tunnels.borrow_mut() = status.tunnels.clone();
        self.rebuild_list();
        if status.tunnels.is_empty() {
            *self.selected.borrow_mut() = None;
            self.stack.set_visible_child(&self.empty);
            return;
        }
        let sel = self.selected.borrow().clone();
        if let Some(ref name) = sel {
            if let Some(t) = status.tunnels.iter().find(|x| x.name == *name) {
                self.show_detail(t);
                return;
            }
            *self.selected.borrow_mut() = None;
        }
        if let Some(r) = self.list.row_at_index(0) {
            self.list.select_row(Some(&r));
        }
    }

    /// Applies JSON from a successful helper run (same shape as `status`).
    fn apply_status_from_helper_ok(&self, out: &str, toast: &adw::ToastOverlay) {
        match parse_status_json(out) {
            Ok(status) => {
                if !status.warnings.is_empty() {
                    show_toast(
                        toast,
                        format!("Warnings:\n{}", status.warnings.join("\n")),
                    );
                }
                self.apply_status_response(&status);
            }
            Err(e) => show_toast(toast, format!("Could not refresh list: {e}")),
        }
    }

    fn rebuild_list(&self) {
        while let Some(c) = self.list.first_child() {
            self.list.remove(&c);
        }
        let tunnels = self.tunnels.borrow().clone();
        let selected_name = self.selected.borrow().clone();
        if tunnels.is_empty() {
            self.stack.set_visible_child(&self.empty);
            return;
        }
        for t in tunnels {
            let row = adw::ActionRow::new();
            row.add_css_class("wg-tunnel-row");
            let is_selected = selected_name.as_deref() == Some(t.name.as_str());
            if is_selected {
                row.add_css_class("wg-tunnel-current");
                row.set_title(&format!("● {}", t.name));
            } else {
                row.set_title(&t.name);
            }
            let sub = format!(
                "{} · {}",
                if t.interface_up {
                    "Connected"
                } else {
                    "Disconnected"
                },
                if t.addresses.is_empty() {
                    "no address".into()
                } else {
                    t.addresses.join(", ")
                }
            );
            row.set_subtitle(&sub);
            row.set_activatable(true);
            self.list.append(&row);
        }
    }

    fn show_detail(&self, tunnel: &TunnelStatus) {
        while let Some(c) = self.detail_root.first_child() {
            self.detail_root.remove(&c);
        }

        let title = gtk::Label::new(Some(&tunnel.name));
        title.add_css_class("title-1");
        title.set_halign(gtk::Align::Start);
        title.set_wrap(true);
        self.detail_root.append(&title);

        let state = gtk::Label::new(Some(if tunnel.interface_up {
            "Connected"
        } else {
            "Disconnected"
        }));
        state.set_halign(gtk::Align::Start);
        state.add_css_class(if tunnel.interface_up {
            "wg-state-up"
        } else {
            "wg-state-down"
        });
        self.detail_root.append(&state);

        let addr = if tunnel.addresses.is_empty() {
            "—".to_string()
        } else {
            tunnel.addresses.join(", ")
        };
        let dns = if tunnel.dns.is_empty() {
            "—".to_string()
        } else {
            tunnel.dns.join(", ")
        };
        let lp = tunnel
            .listen_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".into());
        let cfg = if tunnel.has_config_file {
            tunnel.config_path.clone()
        } else {
            "No configuration file".into()
        };

        let prefs = gtk::Box::new(gtk::Orientation::Vertical, 0);
        prefs.add_css_class("wg-details-card");
        add_pref_row(&prefs, "Addresses", &addr);
        add_pref_row(&prefs, "DNS", &dns);
        add_pref_row(&prefs, "Listen port", &lp);
        add_pref_row(&prefs, "Configuration", &cfg);
        if let Some(last) = prefs.last_child() {
            prefs.remove(&last);
        }
        self.detail_root.append(&prefs);

        let peers_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
        peers_box.set_margin_top(18);
        build_peer_rows(&peers_box, tunnel);
        self.detail_root.append(&peers_box);

        let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        btn_row.set_margin_top(18);

        let connect = gtk::Button::with_label(if tunnel.interface_up {
            "Disconnect"
        } else {
            "Connect"
        });
        if tunnel.interface_up {
            connect.add_css_class("destructive-action");
            connect.add_css_class("wg-disconnect");
        } else {
            connect.add_css_class("suggested-action");
            connect.add_css_class("wg-connect");
        }
        connect.set_sensitive(tunnel.has_config_file);

        let name = tunnel.name.clone();
        let up = tunnel.interface_up;
        let toast = self.toast_overlay.clone();
        let this = self.clone();
        let connect_click = connect.clone();
        connect.connect_clicked(move |_| {
            connect_click.set_sensitive(false);
            let args = if up {
                vec!["down".into(), name.clone()]
            } else {
                vec!["up".into(), name.clone()]
            };
            let toast_c = toast.clone();
            let this_c = this.clone();
            let connect_weak = connect_click.downgrade();
            this.spawn_privileged(args, move |res| {
                match res {
                    Ok(out) => this_c.apply_status_from_helper_ok(&out, &toast_c),
                    Err(e) => show_toast(&toast_c, e),
                }
                if let Some(b) = connect_weak.upgrade() {
                    b.set_sensitive(true);
                }
            });
        });

        let del = gtk::Button::with_label("Delete…");
        del.add_css_class("destructive-action");
        del.add_css_class("wg-delete");
        del.set_sensitive(tunnel.has_config_file);
        let name_d = tunnel.name.clone();
        let window = self.window.clone();
        let toast_d = self.toast_overlay.clone();
        let this_d = self.clone();
        del.connect_clicked(move |_| {
            let dialog = adw::AlertDialog::new(
                Some(&format!("Delete tunnel “{name_d}”?")),
                Some("This removes the configuration file from /etc/wireguard. The interface will be brought down first."),
            );
            dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
            dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");
            let name_dd = name_d.clone();
            dialog.choose(
                &window,
                None::<&gio::Cancellable>,
                {
                    let toast_d = toast_d.downgrade();
                    let this_d = this_d.clone();
                    let name_dd = name_dd.clone();
                    move |answer| {
                    if answer.as_str() != "delete" {
                        return;
                    }
                    let Some(toast_d) = toast_d.upgrade() else {
                        return;
                    };
                    let args = vec!["delete".into(), name_dd.clone()];
                    let toast_e = toast_d.clone();
                    let this_e = this_d.clone();
                    this_d.spawn_privileged(args, move |r| {
                        match r {
                            Ok(out) => {
                                *this_e.selected.borrow_mut() = None;
                                this_e.apply_status_from_helper_ok(&out, &toast_e);
                            }
                            Err(e) => show_toast(&toast_e, e),
                        }
                    });
                }
                },
            );
        });

        let edit = gtk::Button::with_label("Edit…");
        edit.set_sensitive(tunnel.has_config_file);
        let edit_name = tunnel.name.clone();
        let edit_window = self.window.clone();
        let edit_app = self.clone();
        edit.connect_clicked(move |_| {
            open_edit_window(&edit_window, &edit_app, edit_name.clone());
        });

        btn_row.append(&connect);
        btn_row.append(&edit);
        btn_row.append(&del);
        self.detail_root.append(&btn_row);

        self.stack.set_visible_child(
            self.stack
                .child_by_name("detail")
                .as_ref()
                .expect("detail page"),
        );
    }
}

fn open_create_window(parent: &gtk::ApplicationWindow, app: &App) {
    let win = adw::Window::new();
    win.set_transient_for(Some(parent));
    win.set_modal(true);
    win.set_default_size(520, 640);
    win.set_title(Some("New tunnel"));

    let toast_o = app.toast_overlay.clone();
    let this = app.clone();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    header.set_show_end_title_buttons(true);
    toolbar.add_top_bar(&header);

    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::new();
    group.set_title("Tunnel");
    group.set_description(Some("Creates /etc/wireguard/<name>.conf. Keys are generated on the privileged helper."));

    let name_row = adw::EntryRow::new();
    name_row.set_title("Name");
    name_row.set_show_apply_button(false);

    let addr_row = adw::EntryRow::new();
    addr_row.set_title("Addresses (comma-separated CIDRs)");
    addr_row.set_text("10.0.0.2/32");

    let dns_row = adw::EntryRow::new();
    dns_row.set_title("DNS (optional, comma-separated)");

    let port_row = adw::EntryRow::new();
    port_row.set_title("Listen port (optional)");

    group.add(&name_row);
    group.add(&addr_row);
    group.add(&dns_row);
    group.add(&port_row);

    let peer_group = adw::PreferencesGroup::new();
    peer_group.set_title("Peer");
    let pk_row = adw::EntryRow::new();
    pk_row.set_title("Public key");
    let ep_row = adw::EntryRow::new();
    ep_row.set_title("Endpoint (host:port, optional)");
    let allowed_row = adw::EntryRow::new();
    allowed_row.set_title("Allowed IPs");
    allowed_row.set_text("0.0.0.0/0, ::/0");
    let ka_row = adw::EntryRow::new();
    ka_row.set_title("Persistent keepalive (seconds, optional)");
    peer_group.add(&pk_row);
    peer_group.add(&ep_row);
    peer_group.add(&allowed_row);
    peer_group.add(&ka_row);

    page.add(&group);
    page.add(&peer_group);
    toolbar.set_content(Some(&page));

    let cancel = gtk::Button::with_label("Cancel");
    let create = gtk::Button::with_label("Create");
    create.add_css_class("suggested-action");
    let start_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    start_box.append(&cancel);
    start_box.append(&create);
    header.pack_end(&start_box);

    {
        let win_weak = win.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(win) = win_weak.upgrade() {
                win.close();
            }
        });
    }
    {
        let win_weak = win.downgrade();
        let name_row_weak = name_row.downgrade();
        let addr_row_weak = addr_row.downgrade();
        let dns_row_weak = dns_row.downgrade();
        let port_row_weak = port_row.downgrade();
        let pk_row_weak = pk_row.downgrade();
        let ep_row_weak = ep_row.downgrade();
        let allowed_row_weak = allowed_row.downgrade();
        let ka_row_weak = ka_row.downgrade();
        let toast_o_weak = toast_o.downgrade();
        let this = this.clone();
        create.connect_clicked(move |_| {
        let Some(win) = win_weak.upgrade() else {
            return;
        };
        let Some(name_row) = name_row_weak.upgrade() else {
            return;
        };
        let Some(addr_row) = addr_row_weak.upgrade() else {
            return;
        };
        let Some(dns_row) = dns_row_weak.upgrade() else {
            return;
        };
        let Some(port_row) = port_row_weak.upgrade() else {
            return;
        };
        let Some(pk_row) = pk_row_weak.upgrade() else {
            return;
        };
        let Some(ep_row) = ep_row_weak.upgrade() else {
            return;
        };
        let Some(allowed_row) = allowed_row_weak.upgrade() else {
            return;
        };
        let Some(ka_row) = ka_row_weak.upgrade() else {
            return;
        };
        let Some(toast_o) = toast_o_weak.upgrade() else {
            return;
        };
        let name = name_row.text().trim().to_string();
        if let Err(m) = wireguard_gui_common::validate_tunnel_name(&name) {
            show_toast(&toast_o, m);
            return;
        }
        let addresses: Vec<String> = addr_row
            .text()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if addresses.is_empty() {
            show_toast(&toast_o, "At least one address is required");
            return;
        }
        let dns: Vec<String> = dns_row
            .text()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let listen_port = if port_row.text().trim().is_empty() {
            None
        } else {
            port_row.text().trim().parse().ok()
        };
        let public_key = pk_row.text().trim().to_string();
        if public_key.is_empty() {
            show_toast(&toast_o, "Peer public key is required");
            return;
        }
        let endpoint = {
            let e = ep_row.text().trim().to_string();
            if e.is_empty() {
                None
            } else {
                Some(e)
            }
        };
        let allowed_ips = allowed_row.text().trim().to_string();
        if allowed_ips.is_empty() {
            show_toast(&toast_o, "Allowed IPs is required");
            return;
        }
        let persistent_keepalive = if ka_row.text().trim().is_empty() {
            None
        } else {
            ka_row.text().trim().parse().ok()
        };

        let req = CreateTunnelRequest {
            name: name.clone(),
            addresses,
            dns,
            listen_port,
            generate_keys: true,
            private_key: None,
            peer: CreatePeerRequest {
                public_key,
                endpoint,
                allowed_ips,
                preshared_key: None,
                persistent_keepalive,
            },
        };
        let json = match serde_json::to_string_pretty(&req) {
            Ok(j) => j,
            Err(e) => {
                show_toast(&toast_o, format!("{e}"));
                return;
            }
        };
        let tmp = std::env::temp_dir().join(format!("wireguard-gui-create-{}.json", fast_random()));
        if let Err(e) = std::fs::write(&tmp, &json) {
            show_toast(&toast_o, format!("temp file: {e}"));
            return;
        }
        let path_str = tmp.to_string_lossy().into_owned();
        let args = vec!["create".into(), "--file".into(), path_str.clone()];
        let toast_c = toast_o.clone();
        let win_c = win.clone();
        let this_after = this.clone();
        this.spawn_privileged(args, move |res| {
            let _ = std::fs::remove_file(&tmp);
            match res {
                Ok(out) => {
                    show_toast(&toast_c, format!("Created tunnel “{name}”"));
                    win_c.close();
                    this_after.apply_status_from_helper_ok(&out, &toast_c);
                }
                Err(e) => show_toast(&toast_c, e),
            }
        });
    });
    }

    win.set_content(Some(&toolbar));
    win.present();
}

fn fast_random() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() & 0xffff_ffff) as u32)
        .unwrap_or(1)
}

fn open_import_window(parent: &gtk::ApplicationWindow, app: &App) {
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    let f = gtk::FileFilter::new();
    f.set_name(Some("WireGuard configuration"));
    f.add_pattern("*.conf");
    filters.append(&f);

    let dialog = gtk::FileDialog::builder()
        .title("Import configuration")
        .modal(true)
        .filters(&filters)
        .default_filter(&f)
        .build();

    let this = app.clone();
    let toast = app.toast_overlay.clone();
    dialog.open(
        Some(parent),
        None::<&gio::Cancellable>,
        {
            let this = this.clone();
            let toast = toast.downgrade();
            move |result| {
            let Some(toast) = toast.upgrade() else {
                return;
            };
            let file = match result {
                Ok(f) => f,
                Err(e) if e.matches(gtk::DialogError::Dismissed) => return,
                Err(e) => {
                    show_toast(&toast, e.to_string());
                    return;
                }
            };
            let path = match file.path() {
                Some(p) => p,
                None => {
                    show_toast(&toast, "Could not get file path");
                    return;
                }
            };
            let path_s = path.to_string_lossy().into_owned();
            let args = vec!["import".into(), "--path".into(), path_s];
            let this_i = this.clone();
            let toast_i = toast.clone();
            this.spawn_privileged(args, move |r| {
                match r {
                    Ok(out) => {
                        show_toast(&toast_i, "Import completed");
                        this_i.apply_status_from_helper_ok(&out, &toast_i);
                    }
                    Err(e) => show_toast(&toast_i, e),
                }
            });
        }
        },
    );
}

fn open_edit_window(parent: &gtk::ApplicationWindow, app: &App, name: String) {
    let toast = app.toast_overlay.clone();
    let this = app.clone();
    let parent = parent.clone();
    app.spawn_privileged(vec!["read".into(), name.clone()], move |res| {
        let out = match res {
            Ok(out) => out,
            Err(e) => {
                show_toast(&toast, e);
                return;
            }
        };
        let read: ReadTunnelConfigResponse = match serde_json::from_str::<ReadTunnelConfigResponse>(&out) {
            Ok(v) if v.ok => v,
            Ok(_) => {
                show_toast(&toast, "Could not read tunnel configuration");
                return;
            }
            Err(e) => {
                show_toast(&toast, format!("Bad helper response: {e}"));
                return;
            }
        };

        let win = adw::Window::new();
        win.set_transient_for(Some(&parent));
        win.set_modal(true);
        win.set_default_size(760, 560);
        win.set_title(Some(&format!("Edit tunnel: {}", read.name)));

        let toolbar = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        header.set_show_end_title_buttons(true);
        toolbar.add_top_bar(&header);

        let scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();
        let text = gtk::TextView::new();
        text.add_css_class("monospace");
        text.set_wrap_mode(gtk::WrapMode::None);
        text.buffer().set_text(&read.contents);
        scroll.set_child(Some(&text));
        toolbar.set_content(Some(&scroll));

        let cancel = gtk::Button::with_label("Cancel");
        let save = gtk::Button::with_label("Save");
        save.add_css_class("suggested-action");
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        actions.append(&cancel);
        actions.append(&save);
        header.pack_end(&actions);

        {
            let win_weak = win.downgrade();
            cancel.connect_clicked(move |_| {
                if let Some(w) = win_weak.upgrade() {
                    w.close();
                }
            });
        }

        {
            let toast = toast.clone();
            let this = this.clone();
            let win_weak = win.downgrade();
            let text_weak = text.downgrade();
            let name = name.clone();
            save.connect_clicked(move |_| {
                let Some(text) = text_weak.upgrade() else {
                    return;
                };
                let buffer = text.buffer();
                let body = buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string();
                let tmp = std::env::temp_dir().join(format!("wireguard-gui-edit-{}.conf", fast_random()));
                if let Err(e) = std::fs::write(&tmp, &body) {
                    show_toast(&toast, format!("temp file: {e}"));
                    return;
                }
                let args = vec![
                    "update".into(),
                    name.clone(),
                    "--file".into(),
                    tmp.to_string_lossy().into_owned(),
                ];
                let toast_save = toast.clone();
                let this_save = this.clone();
                let win_weak_inner = win_weak.clone();
                this.spawn_privileged(args, move |res| {
                    let _ = std::fs::remove_file(&tmp);
                    match res {
                        Ok(out) => {
                            if let Some(w) = win_weak_inner.upgrade() {
                                w.close();
                            }
                            show_toast(&toast_save, "Tunnel updated");
                            this_save.apply_status_from_helper_ok(&out, &toast_save);
                        }
                        Err(e) => show_toast(&toast_save, e),
                    }
                });
            });
        }

        win.set_content(Some(&toolbar));
        win.present();
    });
}

fn main() {
    // Some Mesa/EGL warnings are emitted very early. Re-exec once with renderer
    // env configured so the final process starts with those vars already set.
    if std::env::var_os("WG_GUI_REEXEC_DONE").is_none() {
        if let Ok(exe) = std::env::current_exe() {
            let mut cmd = std::process::Command::new(exe);
            cmd.env("WG_GUI_REEXEC_DONE", "1");
            if std::env::var_os("GSK_RENDERER").is_none() {
                cmd.env("GSK_RENDERER", "cairo");
            }
            if std::env::var_os("LIBGL_DRI3_DISABLE").is_none() {
                cmd.env("LIBGL_DRI3_DISABLE", "1");
            }
            if std::env::var_os("MESA_DRI3_DISABLE").is_none() {
                cmd.env("MESA_DRI3_DISABLE", "1");
            }
            if std::env::var_os("LIBGL_ALWAYS_SOFTWARE").is_none() {
                cmd.env("LIBGL_ALWAYS_SOFTWARE", "1");
            }
            match cmd.status() {
                Ok(status) => std::process::exit(status.code().unwrap_or(0)),
                Err(_) => {
                    // Fall through and continue in current process if re-exec fails.
                }
            }
        }
    }

    // Avoid noisy EGL/DRI3 warnings on some X11/Mesa setups by using GTK's
    // software renderer unless the user explicitly selected a renderer.
    if std::env::var_os("GSK_RENDERER").is_none() {
        std::env::set_var("GSK_RENDERER", "cairo");
    }
    // On systems without working DRI3, Mesa may emit startup warnings.
    // Disabling DRI3 for this process avoids those warnings and keeps rendering stable.
    if std::env::var_os("LIBGL_DRI3_DISABLE").is_none() {
        std::env::set_var("LIBGL_DRI3_DISABLE", "1");
    }
    if std::env::var_os("MESA_DRI3_DISABLE").is_none() {
        std::env::set_var("MESA_DRI3_DISABLE", "1");
    }
    if std::env::var_os("LIBGL_ALWAYS_SOFTWARE").is_none() {
        std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "1");
    }

    let app = adw::Application::builder().application_id(APP_ID).build();

    app.connect_activate(move |application| {
        let window = gtk::ApplicationWindow::builder()
            .application(application)
            .title("WireGuard-GUI")
            .default_width(980)
            .default_height(640)
            .build();
        window.set_hide_on_close(true);
        window.add_css_class("wg-root");
        install_tech_theme();

        let toast_overlay = adw::ToastOverlay::new();

        let split = adw::NavigationSplitView::new();

        let sidebar_toolbar = adw::ToolbarView::new();
        sidebar_toolbar.add_css_class("wg-card");
        sidebar_toolbar.add_css_class("wg-sidebar");
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.add_css_class("wg-sidebar-header");
        sidebar_header.set_show_end_title_buttons(false);
        sidebar_toolbar.add_top_bar(&sidebar_header);

        let refresh = gtk::Button::from_icon_name("view-refresh-symbolic");
        refresh.set_tooltip_text(Some("Refresh"));
        sidebar_header.pack_end(&refresh);

        let list = gtk::ListBox::new();
        list.set_selection_mode(gtk::SelectionMode::Browse);
        list.add_css_class("navigation-sidebar");
        list.add_css_class("wg-sidebar-list");
        let scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .child(&list)
            .build();
        sidebar_toolbar.set_content(Some(&scroll));

        let content_toolbar = adw::ToolbarView::new();
        content_toolbar.add_css_class("wg-card");
        let content_header = adw::HeaderBar::new();
        content_header.set_show_end_title_buttons(false);
        content_toolbar.add_top_bar(&content_header);

        let stack = gtk::Stack::new();
        let empty = adw::StatusPage::builder()
            .title("No tunnels yet")
            .description("Create a new tunnel or import an existing WireGuard configuration. Operations require administrator authentication.")
            .icon_name("network-vpn-symbolic")
            .build();
        stack.add_named(&empty, Some("empty"));

        let detail_scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .build();
        let detail_root = gtk::Box::new(gtk::Orientation::Vertical, 12);
        detail_root.set_margin_top(18);
        detail_root.set_margin_bottom(18);
        detail_root.set_margin_start(18);
        detail_root.set_margin_end(18);
        detail_scroll.set_child(Some(&detail_root));
        stack.add_named(&detail_scroll, Some("detail"));
        stack.set_visible_child(&empty);

        content_toolbar.set_content(Some(&stack));

        let sidebar_page = adw::NavigationPage::new(&sidebar_toolbar, "Tunnels");
        let content_page = adw::NavigationPage::new(&content_toolbar, "Details");
        split.set_sidebar(Some(&sidebar_page));
        split.set_content(Some(&content_page));

        let menu = gio::Menu::new();
        menu.append(Some("New tunnel…"), Some("app.new-tunnel"));
        menu.append(Some("Import…"), Some("app.import"));
        let pop = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .tooltip_text("Primary menu")
            .menu_model(&menu)
            .primary(true)
            .build();
        content_header.pack_end(&pop);

        toast_overlay.set_child(Some(&split));
        window.set_child(Some(&toast_overlay));

        let model = Rc::new(RefCell::new(Vec::<TunnelStatus>::new()));
        let selected = Rc::new(RefCell::new(None::<String>));
        let refreshing = Rc::new(RefCell::new(false));

        let app_state = App {
            tunnels: model.clone(),
            selected: selected.clone(),
            list: list.clone(),
            detail_root: detail_root.clone(),
            stack: stack.clone(),
            empty: empty.clone(),
            toast_overlay: toast_overlay.clone(),
            window: window.clone(),
            refreshing: refreshing.clone(),
        };

        let st_list = app_state.clone();
        list.connect_row_selected(move |_list, row| {
            let Some(row) = row else {
                return;
            };
            let idx = row.index();
            if idx < 0 {
                return;
            }
            let tunnels = st_list.tunnels.borrow();
            let Some(tunnel) = tunnels.get(idx as usize) else {
                return;
            };
            let title = tunnel.name.clone();
            *st_list.selected.borrow_mut() = Some(title.clone());
            st_list.rebuild_list();
            st_list.show_detail(tunnel);
        });

        application.set_accels_for_action("app.new-tunnel", &["<primary>n"]);
        application.set_accels_for_action("app.import", &["<primary>o"]);
        application.set_accels_for_action("app.refresh", &["<primary>r"]);

        let refresh_action = gio::SimpleAction::new("refresh", None);
        let refresh_action_btn = refresh_action.clone();
        let st_r = app_state.clone();
        let toast_r = toast_overlay.clone();
        refresh_action.connect_activate(move |_, _| {
            if *st_r.refreshing.borrow() {
                return;
            }
            *st_r.refreshing.borrow_mut() = true;
            let toast_c = toast_r.clone();
            let st_c = st_r.clone();
            st_r.spawn_privileged(vec!["status".into()], move |res| {
                *st_c.refreshing.borrow_mut() = false;
                match res {
                    Ok(out) => match parse_status_json(&out) {
                        Ok(status) => {
                            if !status.warnings.is_empty() {
                                show_toast(
                                    &toast_c,
                                    format!("Warnings:\n{}", status.warnings.join("\n")),
                                );
                            }
                            st_c.apply_status_response(&status);
                        }
                        Err(e) => show_toast(&toast_c, e),
                    },
                    Err(e) => show_toast(&toast_c, e),
                }
            });
        });
        application.add_action(&refresh_action);

        let new_action = gio::SimpleAction::new("new-tunnel", None);
        let win_n = window.clone();
        let st_n = app_state.clone();
        new_action.connect_activate(move |_, _| {
            open_create_window(&win_n, &st_n);
        });
        application.add_action(&new_action);

        let import_action = gio::SimpleAction::new("import", None);
        let win_i = window.clone();
        let st_i = app_state.clone();
        import_action.connect_activate(move |_, _| {
            open_import_window(&win_i, &st_i);
        });
        application.add_action(&import_action);

        {
            let refresh_action_btn_click = refresh_action_btn.clone();
            refresh.connect_clicked(move |_| {
                refresh_action_btn_click.activate(None);
            });
        }

        let (tray_tx, tray_rx) = mpsc::channel::<TrayEvent>();
        let tray_service = ksni::TrayService::new(TrayState { tx: tray_tx });
        let tray_handle = tray_service.spawn();
        // Keep tray alive for process lifetime.
        let _ = Box::leak(Box::new(tray_handle));

        let win_toggle = window.clone();
        let app_quit = application.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
            while let Ok(event) = tray_rx.try_recv() {
                match event {
                    TrayEvent::ToggleWindow => {
                        if win_toggle.is_visible() {
                            win_toggle.set_visible(false);
                        } else {
                            win_toggle.present();
                        }
                    }
                    TrayEvent::Quit => {
                        app_quit.quit();
                        return glib::ControlFlow::Break;
                    }
                }
            }
            glib::ControlFlow::Continue
        });

        window.present();
        show_toast(
            &toast_overlay,
            "Tip: closing the window minimizes to tray.",
        );

        if should_bootstrap_polkit_rule() {
            let toast_polkit = toast_overlay.clone();
            let refresh_after = refresh_action_btn.clone();
            app_state.spawn_privileged(vec!["install-polkit-rule".into()], move |res| {
                match res {
                    Ok(_) => {
                        show_toast(
                            &toast_polkit,
                            "Authentication prompt optimization enabled for future actions.",
                        );
                        // Refresh after rule install so launch doesn't trigger a second auth prompt.
                        refresh_after.activate(None);
                    }
                    Err(e) => {
                        // Non-fatal: app still works with default Polkit behavior.
                        show_toast(
                            &toast_polkit,
                            format!("Could not install prompt-optimization rule: {e}"),
                        );
                    }
                }
            });
        } else {
            refresh_action.activate(None);
        }
    });

    let _ = app.run();
}

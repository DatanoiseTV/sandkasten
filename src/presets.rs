//! Named network-protocol / service presets.
//!
//! A preset is a short token (e.g. `"http"`) that expands into concrete
//! TCP/UDP outbound rules plus any needed flags (ICMP, DNS, etc.). The
//! user gets ergonomic high-level names in the profile; the downstream
//! SBPL/nftables generators still see concrete `host:port` entries.
//!
//! **Kernel sandboxes filter at L3/L4 — we cannot distinguish RTP from
//! arbitrary UDP at the kernel layer.** Presets like `rtp` or `webrtc`
//! expand to the standard UDP port ranges those protocols use; any
//! traffic on those ports is then allowed.

use crate::config::Profile;

pub fn expand(profile: &mut Profile) {
    for name in profile.network.presets.clone() {
        apply_preset(profile, &name);
    }
}

fn apply_preset(p: &mut Profile, name: &str) {
    let add_tcp = |p: &mut Profile, ep: &str| {
        if !p.network.outbound_tcp.iter().any(|x| x == ep) {
            p.network.outbound_tcp.push(ep.into());
        }
    };
    let add_udp = |p: &mut Profile, ep: &str| {
        if !p.network.outbound_udp.iter().any(|x| x == ep) {
            p.network.outbound_udp.push(ep.into());
        }
    };
    match name.to_ascii_lowercase().as_str() {
        // ─── web ──────────────────────────────────────────
        "http" => add_tcp(p, "*:80"),
        "https" => add_tcp(p, "*:443"),
        "web" => {
            add_tcp(p, "*:80");
            add_tcp(p, "*:443");
            add_udp(p, "*:443"); // QUIC
            p.network.allow_dns = true;
        }
        "quic" => add_udp(p, "*:443"),

        // ─── realtime media ───────────────────────────────
        // RTP / RTCP operate over UDP; standard ephemeral range per RFC 3550
        // + Chrome/Firefox defaults. We allow the RFC-recommended even-port
        // range 16384-32767.
        "rtp" => {
            add_udp(p, "*:16384-32767");
        }
        "sip" => {
            add_udp(p, "*:5060");
            add_udp(p, "*:5061");
            add_tcp(p, "*:5060");
            add_tcp(p, "*:5061");
        }
        "stun" => {
            add_udp(p, "*:3478");
            add_udp(p, "*:5349");
            add_tcp(p, "*:3478");
            add_tcp(p, "*:5349");
        }
        "webrtc" => {
            apply_preset(p, "stun");
            apply_preset(p, "rtp");
        }

        // ─── remote access ────────────────────────────────
        "ssh" => add_tcp(p, "*:22"),
        "rdp" => add_tcp(p, "*:3389"),
        "vnc" => add_tcp(p, "*:5900-5909"),

        // ─── mail ─────────────────────────────────────────
        "smtp" => add_tcp(p, "*:25"),
        "smtps" => {
            add_tcp(p, "*:465");
            add_tcp(p, "*:587");
        }
        "imap" => add_tcp(p, "*:143"),
        "imaps" => add_tcp(p, "*:993"),
        "pop3" => add_tcp(p, "*:110"),
        "pop3s" => add_tcp(p, "*:995"),

        // ─── file transfer ────────────────────────────────
        "ftp" => {
            add_tcp(p, "*:20");
            add_tcp(p, "*:21");
        }
        "ftps" => add_tcp(p, "*:990"),
        "sftp" => add_tcp(p, "*:22"),
        "git" => add_tcp(p, "*:9418"),

        // ─── directory / auth ────────────────────────────
        "ldap" => add_tcp(p, "*:389"),
        "ldaps" => add_tcp(p, "*:636"),
        "kerberos" => {
            add_tcp(p, "*:88");
            add_udp(p, "*:88");
        }

        // ─── databases / caches ──────────────────────────
        "mysql" => add_tcp(p, "*:3306"),
        "postgres" | "postgresql" => add_tcp(p, "*:5432"),
        "redis" => add_tcp(p, "*:6379"),
        "memcached" => add_tcp(p, "*:11211"),
        "mongodb" | "mongo" => add_tcp(p, "*:27017"),
        "cassandra" => add_tcp(p, "*:9042"),
        "elastic" | "elasticsearch" => add_tcp(p, "*:9200"),

        // ─── messaging / IRC / chat ──────────────────────
        "irc" => add_tcp(p, "*:6667"),
        "ircs" => add_tcp(p, "*:6697"),
        "xmpp" => add_tcp(p, "*:5222"),
        "matrix" => add_tcp(p, "*:8448"),
        "mqtt" => add_tcp(p, "*:1883"),
        "mqtts" => add_tcp(p, "*:8883"),

        // ─── time / discovery ────────────────────────────
        "ntp" => add_udp(p, "*:123"),
        "mdns" => add_udp(p, "*:5353"),
        "dhcp" => {
            add_udp(p, "*:67");
            add_udp(p, "*:68");
        }
        "dns" => {
            p.network.allow_dns = true;
        }

        // ─── network diagnostics ─────────────────────────
        "ping" => {
            p.network.allow_icmp = true;
            p.network.allow_icmpv6 = true;
        }
        "tcpdump" | "pcap" | "wireshark" => {
            // Packet capture requires raw sockets. Inside a user namespace
            // we hold CAP_NET_RAW for the sandbox's private netns, which is
            // enough for AF_PACKET on its own interfaces.
            p.network.allow_raw_sockets = true;
            p.network.allow_icmp = true;
            p.network.allow_icmpv6 = true;
        }
        "nmap" => {
            // nmap falls back to TCP connect scans without raw sockets but
            // SYN / ICMP / UDP scans need them. Grant both.
            p.network.allow_raw_sockets = true;
            p.network.allow_icmp = true;
            p.network.allow_icmpv6 = true;
            p.network.allow_dns = true;
        }

        // ─── VPN / tunnels ───────────────────────────────
        "wireguard" => {
            // Default WG port. Users running on a custom port should list
            // that explicitly in outbound_udp.
            add_udp(p, "*:51820");
        }
        "openvpn" => {
            add_udp(p, "*:1194");
            add_tcp(p, "*:1194");
        }
        "tailscale" => {
            // Tailscale control plane over HTTPS + DERP, plus WireGuard.
            add_tcp(p, "*:443");
            add_udp(p, "*:41641"); // DERP default
            add_udp(p, "*:3478"); // STUN
            p.network.allow_dns = true;
        }
        "ipsec" | "strongswan" => {
            add_udp(p, "*:500");
            add_udp(p, "*:4500");
        }
        "wireguard-all-udp" => {
            // If you don't know the port and trust the peer, allow any UDP.
            add_udp(p, "*:*");
        }

        // ─── games ───────────────────────────────────────
        "minecraft" | "minecraft-java" => {
            add_tcp(p, "*:25565");
        }
        "minecraft-bedrock" => {
            add_udp(p, "*:19132");
            add_udp(p, "*:19133");
        }
        "steam" => {
            // Steamworks control ports. Extensive list from Valve's docs.
            add_tcp(p, "*:27015");
            add_tcp(p, "*:27036");
            add_udp(p, "*:27015");
            add_udp(p, "*:27031-27036");
            add_udp(p, "*:4380");
            add_tcp(p, "*:443"); // Steam client calls out over 443 for auth
            p.network.allow_dns = true;
        }
        "source-engine" | "valve-source" => {
            // CS:GO, TF2, Left 4 Dead, Garry's Mod, etc.
            add_udp(p, "*:27000-27100");
            add_tcp(p, "*:27015");
        }
        "quake3" | "idtech3" => {
            add_udp(p, "*:27960-27969");
        }
        "teamspeak" => {
            add_udp(p, "*:9987");
            add_tcp(p, "*:10011");
            add_tcp(p, "*:30033");
        }
        "discord-voice" => {
            // Discord RTP via a large UDP range, plus control.
            add_udp(p, "*:50000-65535");
            add_tcp(p, "*:443");
        }
        "riot-games" => {
            // League of Legends, Valorant — wide UDP ephemeral + TCP control.
            add_udp(p, "*:5000-5500");
            add_tcp(p, "*:2099");
            add_tcp(p, "*:5222");
            add_tcp(p, "*:5223");
        }

        other => {
            eprintln!("sandkasten ⚠ unknown preset {other:?} — ignored (see README for the list)");
        }
    }
}

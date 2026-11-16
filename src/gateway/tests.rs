#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
use xguard_wireguard_rs::Kernel;
#[cfg(any(target_os = "macos", target_os = "netbsd"))]
use xguard_wireguard_rs::Userspace;
use xguard_wireguard_rs::WGApi;

use super::*;

#[cfg(any(target_os = "macos", target_os = "netbsd"))]
type WG = WGApi<Userspace>;
#[cfg(not(any(target_os = "macos", target_os = "netbsd")))]
type WG = WGApi<Kernel>;

#[tokio::test]
async fn test_configuration_comparison() {
    let old_config = InterfaceConfiguration {
        name: "gateway".to_string(),
        private_key: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
        addresses: vec!["10.6.1.1/24".parse().unwrap()],
        port: 50051,
        mtu: 1420,
        fwmark: 0,
    };

    let old_peers = vec![
        Peer {
            pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
            allowed_ips: vec!["10.6.1.2/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
        Peer {
            pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
            allowed_ips: vec!["10.6.1.3/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
    ];
    let old_peers_map = old_peers
        .clone()
        .into_iter()
        .map(|peer| (peer.pubkey.clone(), peer))
        .collect();

    let wgapi = WG::new("wg0").unwrap();
    let config = Config::default();
    let gateway = Gateway {
        config,
        interface_configuration: Some(old_config.clone()),
        peers: old_peers_map,
        wgapi: Arc::new(Mutex::new(wgapi)),
        connected: Arc::new(AtomicBool::new(false)),
        client_tx: None,
        tls_config: None,
    };

    // new config is the same
    let new_config = old_config.clone();
    let new_peers = old_peers.clone();
    assert!(!gateway.is_interface_config_changed(&new_config, &new_peers));

    // only interface config is different
    let new_config = InterfaceConfiguration {
        name: "gateway".to_string(),
        private_key: "FGqcPuaSlGWC2j50TBA4jHgiefPgQQcgTNLwzKUzBS8=".to_string(),
        addresses: vec!["10.6.1.2/24".parse().unwrap()],
        port: 50051,
        mtu: 1420,
        fwmark: 0,
    };
    let new_peers = old_peers.clone();
    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer was removed
    let new_config = old_config.clone();
    let mut new_peers = old_peers.clone();
    new_peers.pop();

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer was added
    let new_config = old_config.clone();
    let mut new_peers = old_peers.clone();
    new_peers.push(Peer {
        pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
        allowed_ips: vec!["10.6.1.4/24".to_string()],
        preshared_key: None,
        keepalive_interval: None,
    });

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer pubkey changed
    let new_config = old_config.clone();
    let new_peers = vec![
        Peer {
            pubkey: "VOCXuGWKz3PcdFba8pl7bFO/W4OG8sPet+w9Eb1LECk=".to_string(),
            allowed_ips: vec!["10.6.1.2/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
        Peer {
            pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
            allowed_ips: vec!["10.6.1.3/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
    ];

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer IP changed
    let new_config = old_config.clone();
    let new_peers = vec![
        Peer {
            pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
            allowed_ips: vec!["10.6.1.2/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
        Peer {
            pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
    ];

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer preshared key changed
    let new_config = old_config.clone();
    let new_peers = vec![
        Peer {
            pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
            allowed_ips: vec!["10.6.1.2/24".to_string()],
            preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
            keepalive_interval: None,
        },
        Peer {
            pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
    ];

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));

    // peer keepalive interval changed
    let new_config = old_config.clone();
    let new_peers = vec![
        Peer {
            pubkey: "+Oj0nZZ3iVH9WvKU9gM2eajJqY0hnzN5PkI4bvblgWo=".to_string(),
            allowed_ips: vec!["10.6.1.2/24".to_string()],
            preshared_key: Some("VGhpc2lzdGhlcGFzc3dvcmQzMWNoYXJhY3RlcnNsbwo=".into()),
            keepalive_interval: Some(15),
        },
        Peer {
            pubkey: "m7ZxDjk4sjpzgowerQqycBvOz2n/nkswCdv24MEYVGA=".to_string(),
            allowed_ips: vec!["10.6.1.4/24".to_string()],
            preshared_key: None,
            keepalive_interval: None,
        },
    ];

    assert!(gateway.is_interface_config_changed(&new_config, &new_peers));
}

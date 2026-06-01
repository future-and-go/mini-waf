use std::path::Path;

fn configs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

#[test]
fn challenge_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("challenge.yaml");
    waf_engine::challenge::ChallengeConfig::from_path(&path)
        .expect("configs/challenge.yaml must parse through ChallengeConfig");
}

#[test]
fn ddos_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("ddos.yaml");
    waf_engine::checks::ddos::DdosFileConfig::from_path(&path)
        .expect("configs/ddos.yaml must parse through DdosFileConfig");
}

#[test]
fn device_fp_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("device-fp.yaml");
    waf_engine::device_fp::config::DeviceFpConfig::from_path(&path)
        .expect("configs/device-fp.yaml must parse through DeviceFpConfig");
}

#[test]
fn rate_limit_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("rate-limit.yaml");
    waf_engine::checks::rate_limit::RateLimitFileConfig::from_path(&path)
        .expect("configs/rate-limit.yaml must parse through RateLimitFileConfig");
}

#[test]
fn relay_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("relay.yaml");
    waf_engine::relay::config::RelayConfig::from_yaml_path(&path)
        .expect("configs/relay.yaml must parse through RelayConfig");
}

#[test]
fn risk_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("risk.yaml");
    waf_engine::risk::config::RiskConfig::from_path(&path).expect("configs/risk.yaml must parse through RiskConfig");
}

#[test]
fn tx_velocity_yaml_loads_through_engine_parser() {
    let path = configs_dir().join("tx-velocity.yaml");
    waf_engine::checks::tx_velocity::TxVelocityFileConfig::from_path(&path)
        .expect("configs/tx-velocity.yaml must parse through TxVelocityFileConfig");
}

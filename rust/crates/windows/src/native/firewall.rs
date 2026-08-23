//! Windows Firewall through the `INetFwPolicy2` COM object, instead of
//! `netsh advfirewall` or `Set-NetFirewallProfile`.
//!
//! The profile settings are addressed by enum value, so unlike the shell paths
//! nothing here depends on the display language. It also replaces a PowerShell
//! launch per call, which dominated the runtime of the firewall task.

use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
};
use windows::Win32::System::Com::{
    CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::core::GUID;

/// CLSID of the NetFwPolicy2 coclass (hnetcfg.dll).
const NET_FW_POLICY2_CLSID: GUID = GUID::from_u128(0xe2b3c97f_6ae1_41ac_817a_f6f92166d7dd);

const PROFILES: [(&str, NET_FW_PROFILE_TYPE2); 3] = [
    ("Domain", NET_FW_PROFILE2_DOMAIN),
    ("Private", NET_FW_PROFILE2_PRIVATE),
    ("Public", NET_FW_PROFILE2_PUBLIC),
];

/// State of one firewall profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileState {
    pub profile: String,
    pub enabled: bool,
    pub blocks_inbound_by_default: bool,
}

fn policy() -> Result<INetFwPolicy2, String> {
    unsafe {
        // Already-initialised is a normal outcome, not a failure: another part of
        // the process may have initialised COM on this thread first.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        CoCreateInstance(&NET_FW_POLICY2_CLSID, None, CLSCTX_ALL)
            .map_err(|e| format!("the Windows Firewall COM object is unavailable ({e})"))
    }
}

/// Turn the firewall on for all three profiles and set the default actions to
/// block inbound / allow outbound.
///
/// Returns the profiles configured, or the reason it could not be done.
pub fn enable_all_profiles() -> Result<Vec<String>, String> {
    let policy = policy()?;
    let mut configured = Vec::with_capacity(PROFILES.len());

    unsafe {
        for (name, profile) in PROFILES {
            policy
                .put_FirewallEnabled(profile, VARIANT_TRUE)
                .map_err(|e| format!("could not enable the {name} profile ({e})"))?;
            policy
                .put_DefaultInboundAction(profile, NET_FW_ACTION_BLOCK)
                .map_err(|e| format!("could not set the {name} inbound action ({e})"))?;
            policy
                .put_DefaultOutboundAction(profile, NET_FW_ACTION_ALLOW)
                .map_err(|e| format!("could not set the {name} outbound action ({e})"))?;
            configured.push(name.to_string());
        }
    }

    Ok(configured)
}

/// Current state of each profile, or `None` when the policy cannot be read.
pub fn query() -> Option<Vec<ProfileState>> {
    let policy = policy().ok()?;
    let mut states = Vec::with_capacity(PROFILES.len());

    unsafe {
        for (name, profile) in PROFILES {
            let enabled = policy.get_FirewallEnabled(profile).ok()? != VARIANT_FALSE;
            let inbound = policy.get_DefaultInboundAction(profile).ok()?;
            states.push(ProfileState {
                profile: name.to_string(),
                enabled,
                blocks_inbound_by_default: inbound == NET_FW_ACTION_BLOCK,
            });
        }
    }

    Some(states)
}

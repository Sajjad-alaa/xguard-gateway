//! XGuard firewall: enforces the policy Core compiles for this location, plus the gateway's own
//! masquerade setting. See `docs/firewall.md` in the XGuard workspace for the design.

pub mod nft;
pub mod policy;
#[cfg(test)]
mod tests;

use self::{
    nft::{ApplyError, Ruleset},
    policy::{Policy, PolicyError},
};
use crate::proto::gateway::FirewallPolicy;

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("invalid firewall policy: {0}")]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error("the firewall is only supported on Linux (nftables)")]
    Unsupported,
}

/// What is currently installed, so identical updates are skipped.
#[derive(Clone, PartialEq, Eq)]
struct Installed {
    interface: String,
    revision: Option<String>,
    masquerade: bool,
}

pub struct Firewall {
    nft: String,
    masquerade: bool,
    filter_priority: i32,
    interface: Option<String>,
    policy: Option<Policy>,
    installed: Option<Installed>,
    synced: bool,
}

impl Firewall {
    #[must_use]
    pub fn new(masquerade: bool, filter_priority: Option<i32>) -> Self {
        Self {
            // Unit tests must never change the host's ruleset; they check rendering separately.
            nft: if cfg!(test) { "true" } else { "nft" }.into(),
            masquerade,
            filter_priority: filter_priority.unwrap_or(0),
            interface: None,
            policy: None,
            installed: None,
            synced: false,
        }
    }

    /// Uses `program` instead of `nft` from `PATH`.
    #[must_use]
    pub fn with_nft(mut self, program: impl Into<String>) -> Self {
        self.nft = program.into();
        self
    }

    /// Sets the WireGuard interface and the policy together, applying at most once. Used for a
    /// full configuration from Core, where an absent policy means the firewall is off.
    ///
    /// An invalid policy is refused and the current one stays in force.
    pub fn configure(
        &mut self,
        interface: &str,
        policy: Option<FirewallPolicy>,
    ) -> Result<(), FirewallError> {
        let policy = policy.map(Policy::try_from).transpose()?;
        self.interface = Some(interface.to_string());
        self.policy = policy;
        self.sync()
    }

    /// Replaces the policy; `None` turns packet filtering off (masquerade stays).
    ///
    /// An invalid policy is refused and the current one stays in force.
    pub fn set_policy(&mut self, policy: Option<FirewallPolicy>) -> Result<(), FirewallError> {
        self.policy = policy.map(Policy::try_from).transpose()?;
        self.sync()
    }

    /// Removes everything XGuard installed, for example when the interface is torn down.
    pub fn clear(&mut self) -> Result<(), FirewallError> {
        self.interface = None;
        self.policy = None;
        self.sync()
    }

    fn wanted(&self) -> Option<Installed> {
        let interface = self.interface.clone()?;
        let ruleset = self.ruleset(&interface);
        (!ruleset.is_empty()).then(|| Installed {
            interface,
            revision: self.policy.as_ref().map(|p| p.revision.clone()),
            masquerade: self.masquerade,
        })
    }

    fn ruleset<'a>(&'a self, interface: &'a str) -> Ruleset<'a> {
        Ruleset {
            interface,
            filter_priority: self.filter_priority,
            policy: self.policy.as_ref(),
            masquerade: self.masquerade,
        }
    }

    fn sync(&mut self) -> Result<(), FirewallError> {
        let wanted = self.wanted();
        let first = !self.synced;
        self.synced = true;

        if wanted.is_none() && self.installed.is_none() {
            // Nothing to install. A table left by an earlier run is cleared once, best effort, so
            // gateways that never use the firewall don't need nft at all.
            if first
                && cfg!(target_os = "linux")
                && let Err(err) = nft::apply(&self.nft, &nft::render(&Self::empty_ruleset()))
            {
                debug!("Could not clear a leftover firewall table: {err}");
            }
            return Ok(());
        }
        // An empty revision means Core did not hash the policy, so it is always applied.
        let unchanged_revision = wanted
            .as_ref()
            .is_some_and(|w| w.revision.as_deref() != Some(""));
        if !first && wanted == self.installed && unchanged_revision {
            debug!("Firewall is already up to date");
            return Ok(());
        }
        if !cfg!(target_os = "linux") {
            return Err(FirewallError::Unsupported);
        }

        let transaction = match &wanted {
            Some(w) => nft::render(&self.ruleset(&w.interface)),
            None => nft::render(&Self::empty_ruleset()),
        };
        nft::apply(&self.nft, &transaction)?;
        match &wanted {
            Some(w) => info!(
                "Applied firewall for {} (revision {}, {} rules, masquerade {})",
                w.interface,
                w.revision.as_deref().unwrap_or("none"),
                self.policy.as_ref().map_or(0, |p| p.rules.len()),
                w.masquerade
            ),
            None => info!("Removed the XGuard firewall table"),
        }
        self.installed = wanted;
        Ok(())
    }

    fn empty_ruleset() -> Ruleset<'static> {
        Ruleset {
            interface: "",
            filter_priority: 0,
            policy: None,
            masquerade: false,
        }
    }
}

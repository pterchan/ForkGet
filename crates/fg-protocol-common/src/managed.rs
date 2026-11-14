//! Shared checks for an explicitly selected, private managed serving endpoint.

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use reqwest::Url;
use tokio::{net::lookup_host, time::timeout};

pub const MANAGED_BACKEND_HOST: &str = "FG_MANAGED_BACKEND_HOST";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

pub struct ManagedBackend {
    hostname: String,
    ip: Ipv4Addr,
}

pub fn valid_managed_role(role: &str) -> bool {
    (1..=32).contains(&role.len())
        && role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !matches!(
            role.to_ascii_lowercase().as_str(),
            "root" | "postgres" | "cloudsqladmin" | "cloudsqlsuperuser"
        )
}

impl ManagedBackend {
    pub async fn load() -> Result<Option<Self>, &'static str> {
        let value = match env::var(MANAGED_BACKEND_HOST) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err(MANAGED_BACKEND_HOST),
        };
        let hostname = canonical_hostname(&value).ok_or(MANAGED_BACKEND_HOST)?;
        let resolved = timeout(LOOKUP_TIMEOUT, lookup_host((hostname.as_str(), 0)))
            .await
            .map_err(|_| MANAGED_BACKEND_HOST)?
            .map_err(|_| MANAGED_BACKEND_HOST)?;
        let ip = single_private_ip(resolved.map(|addr| addr.ip())).ok_or(MANAGED_BACKEND_HOST)?;
        Ok(Some(Self { hostname, ip }))
    }

    pub fn matches_url(&self, url: &Url) -> bool {
        url.query().is_none()
            && url.fragment().is_none()
            && url.port() != Some(0)
            && url.host_str().and_then(canonical_hostname).as_deref() == Some(self.hostname())
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn address(&self, port: u16) -> SocketAddr {
        (self.ip, port).into()
    }
}

fn canonical_hostname(value: &str) -> Option<String> {
    let hostname = value.strip_suffix('.').unwrap_or(value);
    if hostname.is_empty() || hostname.len() > 253 || hostname.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !hostname.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    let hostname = hostname.to_ascii_lowercase();
    if matches!(hostname.as_str(), "localhost" | "localhost.localdomain")
        || hostname.ends_with(".localhost")
    {
        return None;
    }
    Some(hostname)
}

fn single_private_ip(mut resolved: impl Iterator<Item = IpAddr>) -> Option<Ipv4Addr> {
    let IpAddr::V4(first) = resolved.next()? else {
        return None;
    };
    if !first.is_private() || !resolved.all(|ip| ip == IpAddr::V4(first)) {
        return None;
    }
    Some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_exact_dns_identity_and_forbids_connection_overrides() {
        let managed = ManagedBackend {
            hostname: "db.example.internal".to_owned(),
            ip: Ipv4Addr::new(10, 1, 2, 3),
        };
        for dsn in [
            "mysql://user:pass@DB.Example.Internal.:3306/data",
            "postgresql://user:pass@db.example.internal/data",
        ] {
            assert!(Url::parse(dsn).is_ok_and(|url| managed.matches_url(&url)));
        }
        for dsn in [
            "mysql://user:pass@10.1.2.3/data",
            "postgresql://user:pass@other.example.internal/data",
            "postgresql://user:pass@db.example.internal/data?hostaddr=192.0.2.9",
            "mysql://user:pass@db.example.internal:0/data",
        ] {
            assert!(Url::parse(dsn).is_ok_and(|url| !managed.matches_url(&url)));
        }
        for host in [
            "localhost",
            "localhost.localdomain",
            "a.localhost.",
            "127.0.0.1",
            "a..internal",
            "bad-.internal",
        ] {
            assert!(canonical_hostname(host).is_none());
        }
    }

    #[test]
    fn dns_must_select_one_private_ipv4_address() {
        let private = IpAddr::from([10, 1, 2, 3]);
        assert_eq!(
            single_private_ip([private, private].into_iter()),
            Some(Ipv4Addr::new(10, 1, 2, 3))
        );
        for addresses in [
            vec![],
            vec![IpAddr::from([8, 8, 8, 8])],
            vec![IpAddr::from([127, 0, 0, 1])],
            vec![private, IpAddr::from([8, 8, 8, 8])],
            vec![private, IpAddr::from([10, 1, 2, 4])],
        ] {
            assert!(single_private_ip(addresses.into_iter()).is_none());
        }
    }
}

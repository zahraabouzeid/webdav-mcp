//! Reaches the file service someone named. Anyone can enter any address, so an
//! address must never reach this server's own network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Url, redirect};

use crate::config::user_agent;
use crate::dav::{DavClient, Login, LoginForm};
use crate::error::{Result, WebdavError};

const ADDRESS_RULES: &str = "The address must be a public https address.";
const MISSING_LOGIN: &str = "Enter the address, the username and the app password.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    PublicOnly,
    /// For tests, whose stand-in file service runs on this computer.
    Any,
}

pub struct Network {
    http: reqwest::Client,
    addresses: Addresses,
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b)))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let [first, second, ..] = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first == 0x2001 && second == 0x0db8)
        || first == 0x0064)
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

/// Checking when connecting, not only when reading the address, also catches a
/// name that resolves to something else the second time.
struct PublicAddresses;

impl Resolve for PublicAddresses {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let public: Vec<SocketAddr> = found.filter(|address| is_public(address.ip())).collect();
            if public.is_empty() {
                return Err("the name has no public address".into());
            }
            let addresses: Addrs = Box::new(public.into_iter());
            Ok(addresses)
        })
    }
}

fn allowed_url(url: &Url) -> bool {
    let public_host = match url.host() {
        Some(url::Host::Domain(_)) => true,
        Some(url::Host::Ipv4(ip)) => is_public_v4(ip),
        Some(url::Host::Ipv6(ip)) => is_public_v6(ip),
        None => false,
    };
    url.scheme() == "https"
        && public_host
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.port(), None | Some(443))
}

fn client(addresses: Addresses) -> reqwest::Client {
    // A redirect could lead anywhere, and the login would be sent along.
    let builder = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(5))
        .redirect(redirect::Policy::none())
        .no_proxy();
    let builder = match addresses {
        Addresses::Any => builder,
        Addresses::PublicOnly => builder.dns_resolver(Arc::new(PublicAddresses)),
    };
    builder
        .build()
        .expect("the HTTP client has a valid configuration")
}

impl Network {
    pub fn new(addresses: Addresses) -> Self {
        Self {
            http: client(addresses),
            addresses,
        }
    }

    /// The folder all paths start from. A bare host name means the usual place
    /// on Nextcloud and ownCloud.
    fn root_of(&self, address: &str, user: &str) -> Result<Url> {
        let address = address.trim();
        let address = if address.contains("://") {
            address.to_owned()
        } else {
            format!("https://{address}")
        };
        let mut url = Url::parse(&address).map_err(|_| WebdavError::new(ADDRESS_RULES))?;
        if self.addresses == Addresses::PublicOnly && !allowed_url(&url) {
            return Err(WebdavError::new(ADDRESS_RULES));
        }
        let bare = matches!(url.path(), "" | "/");
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| WebdavError::new(ADDRESS_RULES))?;
        if bare {
            segments
                .clear()
                .extend(["remote.php", "dav", "files", user]);
        }
        segments.pop_if_empty().push("");
        drop(segments);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    pub fn client(&self, login: &Login) -> Result<DavClient> {
        let root = Url::parse(&login.root).map_err(|_| WebdavError::new(ADDRESS_RULES))?;
        if self.addresses == Addresses::PublicOnly && !allowed_url(&root) {
            return Err(WebdavError::new(ADDRESS_RULES));
        }
        Ok(DavClient::new(
            self.http.clone(),
            root,
            login.user.clone(),
            login.password.clone(),
        ))
    }

    /// Tries a login on the service, so a mistake shows up while someone is
    /// still on the page.
    pub async fn check(&self, form: &LoginForm) -> Result<Login> {
        let field = |value: &Option<String>| value.as_deref().unwrap_or_default().trim().to_owned();
        let (address, user) = (field(&form.address), field(&form.user));
        let password = form.password.clone().unwrap_or_default();
        if address.is_empty() || user.is_empty() || password.is_empty() {
            return Err(WebdavError::new(MISSING_LOGIN));
        }
        let login = Login {
            root: self.root_of(&address, &user)?.to_string(),
            user,
            password,
            notes: Some(field(&form.notes)).filter(|notes| !notes.is_empty()),
        };
        self.client(&login)?.list("").await?;
        Ok(login)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(address: &str) -> Result<String> {
        Network::new(Addresses::PublicOnly)
            .root_of(address, "ab123456@uni.example")
            .map(|url| url.to_string())
    }

    #[test]
    fn a_host_name_is_enough_for_nextcloud_and_owncloud() {
        let expected = "https://cloud.example/remote.php/dav/files/ab123456@uni.example/";
        assert_eq!(root("cloud.example").expect("root"), expected);
        assert_eq!(root(" https://cloud.example/ ").expect("root"), expected);
    }

    #[test]
    fn a_full_address_is_kept_and_ends_with_a_slash() {
        assert_eq!(
            root("https://cloud.example/remote.php/webdav").expect("root"),
            "https://cloud.example/remote.php/webdav/"
        );
    }

    #[test]
    fn only_public_https_addresses_are_taken() {
        for refused in [
            "http://cloud.example",
            "ftp://cloud.example",
            "https://user:secret@cloud.example",
            "https://cloud.example:8080",
            "127.0.0.1",
            "https://10.0.0.5",
            "https://169.254.169.254/metadata",
            "https://[::1]",
            "https://[::ffff:10.0.0.5]",
            "https://[fd00::1]",
            "not an address",
        ] {
            assert!(root(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn internal_addresses_are_not_public() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "64:ff9b::a00:1",
        ] {
            let ip: IpAddr = address.parse().expect("an address");
            assert!(!is_public(ip), "{address}");
        }
        for address in ["134.130.1.1", "8.8.8.8", "2a00:1450:4001::1"] {
            let ip: IpAddr = address.parse().expect("an address");
            assert!(is_public(ip), "{address}");
        }
    }

    #[tokio::test]
    async fn a_name_for_this_computer_is_refused_when_connecting() {
        let name: Name = "localhost".parse().expect("a name");
        assert!(PublicAddresses.resolve(name).await.is_err());
    }

    #[tokio::test]
    async fn a_login_needs_every_field() {
        let form = LoginForm {
            address: Some("cloud.example".into()),
            user: Some(" ".into()),
            password: Some("app-password".into()),
            notes: None,
        };
        let Err(error) = Network::new(Addresses::PublicOnly).check(&form).await else {
            panic!("a login without a username was accepted");
        };
        assert_eq!(error.to_string(), MISSING_LOGIN);
    }
}

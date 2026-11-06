//! A small built-in list of well-known ad, analytics and tracking domains.
//! Matching is by suffix, so "stats.g.doubleclick.net" matches "doubleclick.net".

pub const DOMAINS: &[&str] = &[
    // Google ads & analytics
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
    "googletagmanager.com", "googletagservices.com", "app-measurement.com", "adservice.google.com",
    "firebaselogging-pa.googleapis.com", "crashlytics.com",
    // Meta, Microsoft, Amazon, TikTok, X, Snap, LinkedIn, Pinterest, Reddit
    "connect.facebook.net", "graph.facebook.com", "pixel.facebook.com", "an.facebook.com",
    "clarity.ms", "bat.bing.com", "amazon-adsystem.com", "analytics.tiktok.com", "ads-twitter.com",
    "analytics.twitter.com", "sc-static.net", "px.ads.linkedin.com", "ct.pinterest.com",
    "events.redditmedia.com",
    // Product analytics & session replay
    "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "heap.io", "heapanalytics.com",
    "fullstory.com", "hotjar.com", "hotjar.io", "mouseflow.com", "logrocket.io", "logrocket.com",
    "posthog.com", "statsig.com", "statsigapi.net", "braze.com",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com", "singular.net", "onesignal.com",
    "intercom.io", "pendo.io", "optimizely.com", "newrelic.com", "nr-data.net", "datadoghq.com",
    "browser-intake-datadoghq.com", "sentry.io", "bugsnag.com", "rollbar.com",
    // Ad tech & data brokers
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com", "rubiconproject.com",
    "pubmatic.com", "openx.net", "casalemedia.com", "scorecardresearch.com", "quantserve.com",
    "demdex.net", "omtrdc.net", "everesttech.net", "bluekai.com", "krxd.net", "exelator.com",
    "rlcdn.com", "liveramp.com", "adsrvr.org", "mathtag.com", "agkn.com", "tapad.com",
    "moatads.com", "doubleverify.com", "adsafeprotected.com", "chartbeat.com", "chartbeat.net",
    "parsely.com", "smartadserver.com", "teads.tv", "yieldmo.com", "3lift.com",
];

pub fn is_tracker(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    DOMAINS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn encrypted_dns() {
        assert!(super::is_encrypted_dns(None, Some("10.0.0.1"), 853));
        assert!(super::is_encrypted_dns(Some("chrome.cloudflare-dns.com"), None, 443));
        assert!(super::is_encrypted_dns(None, Some("1.1.1.1"), 443));
        assert!(!super::is_encrypted_dns(Some("github.com"), Some("1.1.1.1"), 443));
        assert!(super::is_doh_probe("_dns.resolver.arpa"));
        assert!(!super::is_doh_probe("www.apple.com"));
    }

    #[test]
    fn matches_suffix_only_on_label_boundary() {
        assert!(super::is_tracker("stats.g.doubleclick.net"));
        assert!(super::is_tracker("doubleclick.net"));
        assert!(!super::is_tracker("notdoubleclick.net"));
        assert!(!super::is_tracker("github.com"));
    }
}

/// Public encrypted-DNS (DoH/DoT) endpoints. Traffic to these goes around any local resolver.
pub const DOH_HOSTS: &[&str] = &[
    "one.one.one.one", "cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.nextdns.io",
    "doh.opendns.com", "dns.adguard.com", "dns.adguard-dns.com", "doh.cleanbrowsing.org",
    "dns.alidns.com", "doh.dns.sb", "dns.mullvad.net", "doh.mullvad.net", "dns.controld.com",
    "doh.applied-privacy.net", "dns.digitale-gesellschaft.ch",
];

/// Well-known public resolver IPs, for connections whose hostname wasn't captured.
pub const DNS_IPS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "94.140.14.14", "94.140.15.15", "45.90.28.0", "45.90.30.0",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
];

fn host_in(list: &[&str], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Is this connection encrypted DNS? Port 853 is always DoT; port 443 counts when the
/// host is a known DoH endpoint, or the IP is a public resolver and no host was captured.
pub fn is_encrypted_dns(host: Option<&str>, ip: Option<&str>, port: i64) -> bool {
    match port {
        853 => true,
        443 => match host {
            Some(h) => host_in(DOH_HOSTS, h),
            None => ip.is_some_and(|i| DNS_IPS.contains(&i)),
        },
        _ => false,
    }
}

/// Does this DNS lookup look like a device discovering encrypted DNS (so later lookups
/// may bypass the resolver)? Covers DDR probes and the DoH endpoints themselves.
pub fn is_doh_probe(qname: &str) -> bool {
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    q.ends_with("resolver.arpa") || host_in(DOH_HOSTS, &q)
}

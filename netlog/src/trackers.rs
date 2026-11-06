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
    fn matches_suffix_only_on_label_boundary() {
        assert!(super::is_tracker("stats.g.doubleclick.net"));
        assert!(super::is_tracker("doubleclick.net"));
        assert!(!super::is_tracker("notdoubleclick.net"));
        assert!(!super::is_tracker("github.com"));
    }
}

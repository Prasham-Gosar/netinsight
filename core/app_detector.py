"""
app_detector.py
----------------
Best-effort answer to "which application is this traffic for?".

Encrypted traffic hides its content, but it still leaks *labels*:

  1. DNS      - the phone-book lookup:  "youtube.com -> 142.250.1.1".
                Later packets to 142.250.1.1 are probably YouTube.
  2. TLS SNI  - the name spoken when an HTTPS connection starts.
  3. HTTP Host- same idea for plain HTTP.
  4. IP range - a few well-known public addresses (e.g. 8.8.8.8 = Google DNS).
  5. Ports    - weakest clue (443 could be anything).

We remember "IP -> domain" in a small cache and match domains against a
rule table, always preferring the MOST SPECIFIC rule
(meet.google.com beats google.com).

Honest limitation: CDNs share one IP between many sites, and QUIC hides
the SNI, so this is a *best guess*, never 100% accurate.
"""

import ipaddress
from collections import OrderedDict

APP_RULES = {
    "Google Meet": ["meet.google.com", "meetings.google.com"],
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
    "Prime Video": ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net"],
    "Disney+ Hotstar": ["hotstar.com", "hotstarext.com", "disneyplus.com", "bamgrid.com"],
    "Zoom": ["zoom.us", "zoom.com", "zoomgov.com"],
    "Microsoft Teams": ["teams.microsoft.com", "teams.live.com", "skype.com"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "Facebook": ["facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com"],
    "Spotify": ["spotify.com", "scdn.co", "spotifycdn.com"],
    "Steam": ["steampowered.com", "steamcontent.com", "steamstatic.com", "steamgames.com", "steamserver.net"],
    "Discord": ["discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media"],
    "Twitter / X": ["twitter.com", "x.com", "twimg.com", "t.co"],
    "Reddit": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "Telegram": ["telegram.org", "t.me", "telegra.ph"],
    "Snapchat": ["snapchat.com", "sc-cdn.net"],
    "Twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    "GitHub": ["github.com", "githubusercontent.com", "githubassets.com", "github.io"],
    "Claude": ["claude.ai", "anthropic.com", "claude.com"],
    "ChatGPT / OpenAI": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "Slack": ["slack.com", "slack-edge.com"],
    "Canva": ["canva.com"],
    "Wikipedia": ["wikipedia.org", "wikimedia.org"],
    "Amazon": ["amazon.com", "amazon.in", "media-amazon.com", "ssl-images-amazon.com"],
    "AWS / CloudFront": ["amazonaws.com", "cloudfront.net"],
    "Cloudflare": ["cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com"],
    "Akamai CDN": ["akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net"],
    "Fastly CDN": ["fastly.net", "fastlylb.net"],
    "Windows Update": ["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com"],
    "Microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
                  "msn.com", "bing.com", "msftconnecttest.com", "windows.com", "windows.net",
                  "azure.com", "azureedge.net", "outlook.com", "sharepoint.com", "onedrive.com"],
    "Apple": ["apple.com", "icloud.com", "mzstatic.com", "aaplimg.com"],
    "Python / PyPI": ["pypi.org", "pythonhosted.org"],
    "npm": ["npmjs.org", "npmjs.com"],
    "Google": ["google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "gvt1.com",
               "gvt2.com", "google.co.in", "googleadservices.com", "doubleclick.net",
               "googlesyndication.com", "google-analytics.com", "googletagmanager.com",
               "ggpht.com", "recaptcha.net", "firebaseio.com"],
}

# A few real, well-known public addresses (the "known IP ranges" technique)
KNOWN_NETWORKS = [
    (ipaddress.ip_network("8.8.8.0/24"), "Google DNS"),
    (ipaddress.ip_network("8.8.4.0/24"), "Google DNS"),
    (ipaddress.ip_network("1.1.1.0/24"), "Cloudflare DNS"),
    (ipaddress.ip_network("1.0.0.0/24"), "Cloudflare DNS"),
    (ipaddress.ip_network("9.9.9.0/24"), "Quad9 DNS"),
]

# Traffic with no domain clue: label the *service* instead of guessing an app
SYSTEM_SERVICES = {
    "DNS": "DNS", "mDNS": "Local discovery", "SSDP": "Local discovery", "LLMNR": "Local discovery",
    "NetBIOS": "Local discovery", "ARP": "ARP", "ICMP": "ICMP", "ICMPv6": "ICMP",
    "DHCP": "DHCP", "DHCPv6": "DHCP", "NTP": "NTP", "SSH": "SSH", "STUN": "Video/Voice calls (STUN)",
}

CONFIDENCE = {"sni": "high", "http-host": "high", "dns": "medium", "ip-range": "medium",
              "service": "low", "unknown": "none"}

_SUFFIX_TO_APP = {s: app for app, suffixes in APP_RULES.items() for s in suffixes}


def domain_to_app(domain):
    """Longest-suffix match: 'rr1.googlevideo.com' -> YouTube."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    for i in range(len(labels) - 1):          # never match a bare TLD
        app = _SUFFIX_TO_APP.get(".".join(labels[i:]))
        if app:
            return app
    return None


class AppDetector:
    def __init__(self, max_ips=20000):
        self._ip_domain = OrderedDict()   # ip -> (domain, method)
        self._max = max_ips

    def _remember(self, ip, domain, method):
        if not ip or not domain:
            return
        old = self._ip_domain.get(ip)
        if old and old[1] in ("sni", "http-host") and method == "dns":
            return                         # keep the stronger evidence
        self._ip_domain[ip] = (domain, method)
        self._ip_domain.move_to_end(ip)
        if len(self._ip_domain) > self._max:
            self._ip_domain.popitem(last=False)

    def learn_from(self, rec, remote_ip):
        """Update the IP->domain memory from DNS answers, SNI and Host headers."""
        dns = rec.get("dns")
        if dns and dns["qr"] == 1 and dns["qname"]:
            for ip in dns["answers"]:
                self._remember(ip, dns["qname"], "dns")
        if rec.get("sni"):
            self._remember(remote_ip, rec["sni"], "sni")
        if rec.get("http_host"):
            self._remember(remote_ip, rec["http_host"], "http-host")

    def domain_for_ip(self, ip):
        hit = self._ip_domain.get(ip)
        return hit[0] if hit else None

    def classify(self, rec, remote_ip):
        """Return {'app', 'domain', 'method', 'confidence'} for one packet."""
        self.learn_from(rec, remote_ip)

        app_proto = rec.get("app_protocol")
        dns = rec.get("dns")
        if dns and dns["qname"]:                      # DNS packets are system traffic,
            return self._result("DNS", dns["qname"], "service")   # but we keep the name

        domain = method = None
        if rec.get("sni"):
            domain, method = rec["sni"], "sni"
        elif rec.get("http_host"):
            domain, method = rec["http_host"], "http-host"
        elif remote_ip and remote_ip in self._ip_domain:
            domain, method = self._ip_domain[remote_ip]

        if domain:
            app = domain_to_app(domain) or "Other"
            return self._result(app, domain, method)

        if remote_ip:
            try:
                addr = ipaddress.ip_address(remote_ip)
                for net, name in KNOWN_NETWORKS:
                    if addr in net:
                        return self._result(name, None, "ip-range")
            except ValueError:
                pass

        if app_proto in SYSTEM_SERVICES:
            return self._result(SYSTEM_SERVICES[app_proto], None, "service")
        return self._result("Unclassified", None, "unknown")

    @staticmethod
    def _result(app, domain, method):
        return {"app": app, "domain": domain, "method": method,
                "confidence": CONFIDENCE.get(method, "none")}

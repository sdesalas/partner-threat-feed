# Partner Threat Feed

Indicator rules from the Partner Threat Feed, a fictitious threat intelligence partner. Each rule detects the
indicators of one campaign by one threat family: command and control IP addresses and domains, file hashes, payload
URLs, TLS fingerprints, phishing senders, and the registry values and scheduled task names a family uses to persist.

Rules are grouped by threat type (`ransomware`, `infostealer`, `rat`, `loader`, `botnet`, `banking_trojan`,
`cryptominer`, `phishing_kit`, `espionage`), then by family. Every rule is tagged with its family, threat type and
campaign.

The families, campaigns and indicators are made up. IP addresses are in 198.18.0.0/15, which is reserved for
benchmarking, and domains end in `.example`, `.test` or `.invalid`, so the rules install but match no real traffic.

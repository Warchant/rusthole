//! Pure mapping from `etc/hosts` to local records.

use rusthole_core::Config;

use crate::ImportReport;
use crate::map_pihole_toml::hosts_line;

/// Adds the entries of a hosts file as local A and AAAA records.
///
/// The function skips localhost, loopback and `ip6-` entries, and reports each imported entry.
/// A name on `0.0.0.0` or `::` is a manual block: it goes to the report, not to the records.
pub fn map_hosts(text: &str, config: &mut Config, report: &mut ImportReport) {
    for line in text.lines() {
        hosts_line(line, "etc/hosts", true, config, report);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_system_entries() {
        let text = "\
127.0.0.1\tlocalhost
127.0.1.1\tpihole
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
# a comment
192.0.2.20 printer.lan printer # office
2001:db8::20 printer.lan
";
        let mut c = Config::default();
        let mut r = ImportReport::default();
        map_hosts(text, &mut c, &mut r);
        let names: Vec<_> = c
            .local_dns
            .records
            .iter()
            .map(|x| (x.name.as_str(), x.value.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("printer.lan", "192.0.2.20"),
                ("printer", "192.0.2.20"),
                ("printer.lan", "2001:db8::20")
            ]
        );
        assert_eq!(r.translated.len(), 3);
        assert_eq!(r.ignored.len(), 6);
        assert_eq!(r.reported, Vec::<String>::new());
        assert_eq!(c.validate(), []);
    }

    #[test]
    fn unspecified_address_is_a_manual_block_and_is_reported() {
        let text = "0.0.0.0 ads.example\n:: tracker.example\n0.0.0.0 localhost\n";
        let mut c = Config::default();
        let mut r = ImportReport::default();
        map_hosts(text, &mut c, &mut r);
        assert_eq!(c.local_dns.records, []);
        assert_eq!(
            r.reported,
            [
                "etc/hosts: \"ads.example\" on 0.0.0.0 looks like a manual block; not imported; add an exact deny rule for it",
                "etc/hosts: \"tracker.example\" on :: looks like a manual block; not imported; add an exact deny rule for it",
            ]
        );
        assert_eq!(
            r.ignored,
            ["etc/hosts: system entry localhost 0.0.0.0 is not imported"]
        );
    }
}

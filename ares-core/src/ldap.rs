//! LDAP distinguished-name helpers shared by the tool executors and the
//! orchestrator automations.

/// Convert a domain name to an LDAP base DN.
///
/// e.g. `"contoso.local"` -> `"DC=contoso,DC=local"`
///
/// Empty labels are dropped, so a malformed domain (`""`, `"contoso..local"`,
/// `".contoso.local"`) yields a well-formed DN rather than one containing an
/// empty `DC=` component that no directory server will accept. An entirely
/// empty domain therefore produces an empty string, which callers can test
/// with [`str::is_empty`] before splicing the result into a longer DN.
pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_domain() {
        assert_eq!(domain_to_base_dn("contoso.local"), "DC=contoso,DC=local");
    }

    #[test]
    fn fabrikam_domain() {
        assert_eq!(domain_to_base_dn("fabrikam.local"), "DC=fabrikam,DC=local");
    }

    #[test]
    fn child_domain() {
        assert_eq!(
            domain_to_base_dn("child.contoso.local"),
            "DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn deeply_nested_domain() {
        assert_eq!(
            domain_to_base_dn("sub.child.contoso.local"),
            "DC=sub,DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn single_label_domain() {
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }

    #[test]
    fn empty_domain_yields_empty_dn() {
        assert_eq!(domain_to_base_dn(""), "");
    }

    #[test]
    fn empty_labels_are_dropped() {
        assert_eq!(domain_to_base_dn("contoso..local"), "DC=contoso,DC=local");
        assert_eq!(domain_to_base_dn(".contoso.local"), "DC=contoso,DC=local");
        assert_eq!(domain_to_base_dn("contoso.local."), "DC=contoso,DC=local");
    }
}

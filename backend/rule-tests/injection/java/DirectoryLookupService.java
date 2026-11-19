// Test: positive for rule JAVA-INJ-003
// Expected: should_trigger
// Category: injection
// Language: java

package com.acme.vulnerable.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.List;

@Service
public class DirectoryLookupService {

    private final LdapTemplate ldapTemplate;

    @Autowired
    public DirectoryLookupService(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    /**
     * Looks up employee details in the corporate LDAP directory.
     * This method is vulnerable to LDAP injection because the search filter
     * is constructed by concatenating unsanitized user input directly into
     * the LDAP filter string.
     *
     * @param employeeName the employee name submitted from the search form
     * @return list of matching employee display names
     */
    public List<String> findEmployeesByName(String employeeName) {

        String baseDn = "ou=employees,dc=acme,dc=com";

        // VULNERABLE: Unsanitized user input concatenated into LDAP search filter
        String searchFilter = "(&(objectClass=person)(cn=" + employeeName + "))";

        List<String> results = ldapTemplate.search(
                baseDn,
                searchFilter,
                new AttributesMapper<String>() {
                    @Override
                    public String mapFromAttributes(Attributes attributes) throws NamingException {
                        return (String) attributes.get("displayName").get();
                    }
                }
        );

        return results;
    }

    /**
     * Retrieves the group memberships for a given username.
     * Also vulnerable: DN constructed from raw user input.
     */
    public List<String> getGroupMemberships(String username) {

        // VULNERABLE: Unsanitized username used directly in DN construction
        String userDn = "uid=" + username + ",ou=employees,dc=acme,dc=com";
        String groupFilter = "(&(objectClass=groupOfNames)(member=" + userDn + "))";

        return ldapTemplate.search(
                "ou=groups,dc=acme,dc=com",
                groupFilter,
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
        );
    }
}

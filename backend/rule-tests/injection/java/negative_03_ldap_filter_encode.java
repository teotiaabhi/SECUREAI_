// Test: negative for rule JAVA-INJ-003
// Expected: should_not_trigger
// Category: injection
// Language: java

package com.acme.secure.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;
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
     * This method is safe because it encodes user input with LdapEncoder
     * before inserting it into the LDAP filter, neutralizing any special
     * LDAP metacharacters such as *, (, ), \, and NUL.
     *
     * @param employeeName the employee name submitted from the search form
     * @return list of matching employee display names
     */
    public List<String> findEmployeesByName(String employeeName) {

        String baseDn = "ou=employees,dc=acme,dc=com";

        // SAFE: User input encoded before being placed into the search filter
        String sanitizedName = LdapEncoder.filterEncode(employeeName);
        String searchFilter = "(&(objectClass=person)(cn=" + sanitizedName + "))";

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
     * Also safe: both the DN component and filter value are properly encoded.
     */
    public List<String> getGroupMemberships(String username) {

        // SAFE: DN component encoded with nameEncode, filter value with filterEncode
        String encodedUsername = LdapEncoder.nameEncode(username);
        String userDn = "uid=" + encodedUsername + ",ou=employees,dc=acme,dc=com";
        String groupFilter = "(&(objectClass=groupOfNames)(member="
                           + LdapEncoder.filterEncode(userDn) + "))";

        return ldapTemplate.search(
                "ou=groups,dc=acme,dc=com",
                groupFilter,
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
        );
    }
}

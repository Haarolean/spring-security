package org.springframework.security.ldap.authentication.ad;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

public class DefaultActiveDirectoryAuthoritiesPopulator implements LdapAuthoritiesPopulator {

	protected final Log logger = LogFactory.getLog(getClass());

	@Override
	public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
		String[] groups = userData.getStringAttributes("memberOf");
		if (groups == null) {
			this.logger.debug("No values for 'memberOf' attribute.");
			return AuthorityUtils.NO_AUTHORITIES;
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
		}

		return Arrays.stream(groups)
				.map(group -> new SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()))
				.collect(Collectors.toList());
	}
}

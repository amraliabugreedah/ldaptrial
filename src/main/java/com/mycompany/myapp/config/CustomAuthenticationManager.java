package com.mycompany.myapp.config;


import com.mycompany.myapp.domain.Authority;
import com.mycompany.myapp.domain.User;
import com.mycompany.myapp.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;


@Component
@Primary
public class CustomAuthenticationManager implements AuthenticationManager {

    LdapAuthenticationProvider provider = null;

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationManager.class);

    private final UserRepository userRepository;



    private final LdapContextSource ldapContextSource;

    @Autowired
    public CustomAuthenticationManager(UserRepository userRepository, LdapContextSource ldapContextSource) {
        this.userRepository = userRepository;
        this.ldapContextSource = ldapContextSource;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("AUTHENTICATION Login " + authentication.getName());
        log.debug("AUTHENTICATION Password " + authentication.getCredentials().toString());

        BindAuthenticator bindAuth = new BindAuthenticator(ldapContextSource);
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
            "ou=User,ou=ActiveMQ,ou=system", "(objectClass=*)",
            ldapContextSource);

        try {
            System.out.println("wwwoohoo111");
            bindAuth.setUserSearch(userSearch);
            bindAuth.afterPropertiesSet();
            System.out.println("wwwoohoo2222");

        } catch (Exception ex) {
            java.util.logging.Logger
                .getLogger(CustomAuthenticationManager.class.getName())
                .log(Level.SEVERE, null, ex);
            System.out.println("wwwoohoo2121");
        }
        System.out.println("wwwoohoo3333");
        provider = new LdapAuthenticationProvider(bindAuth);

        System.out.println("wwwoohoo4444");
        provider.setUserDetailsContextMapper(new UserDetailsContextMapper() {
            @Override
            public UserDetails mapUserFromContext(DirContextOperations dirContextOperations, String username, Collection<? extends GrantedAuthority> collection) {
                System.out.println("koko2");
                Optional<User> isUser = userRepository.findOneWithAuthoritiesByLogin(username);

                final User user = isUser.get();
                Set<Authority> userAuthorities = user.getAuthorities();
                Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                for (Authority a : userAuthorities) {
                    GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(a.getName());
                    grantedAuthorities.add(grantedAuthority);
                }
                return new org.springframework.security.core.userdetails.User(username, "1", grantedAuthorities);
            }

            @Override
            public void mapUserToContext(UserDetails userDetails, DirContextAdapter dirContextAdapter) {
                System.out.println("hello yooo! ");
            }
        });
        return provider.authenticate(authentication);
    }
}

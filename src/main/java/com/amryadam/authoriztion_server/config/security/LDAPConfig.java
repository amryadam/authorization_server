package com.amryadam.authoriztion_server.config.security;

import com.amryadam.authoriztion_server.services.administration.CustomerUserDetailsService;
import com.amryadam.authoriztion_server.services.administration.JpaUserDetailsService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@Configuration
@AllArgsConstructor
public class LDAPConfig {
    private final JpaUserDetailsService userDetailsService;

    private final CustomerUserDetailsService customerUserDetailsService;


    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");



        //TODO Separate user(ADMIN) from customer during login
        // the services are used in the same other they registered
        auth.userDetailsService(userDetailsService);
        auth.userDetailsService(customerUserDetailsService);
    }
}





package com.amryadam.authoriztion_server.model.administration;

import com.amryadam.authoriztion_server.entities.administration.Customer;
import com.amryadam.authoriztion_server.entities.administration.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;


public class SecurityCustomer implements UserDetails {

    private final Customer customer;

    public SecurityCustomer(Customer customer) {
        this.customer = customer;
    }

    @Override
    public String getUsername() {
        return customer.getName();
    }

    @Override
    public String getPassword() {
        return customer.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(customer
                        .getRoles()
                        .split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

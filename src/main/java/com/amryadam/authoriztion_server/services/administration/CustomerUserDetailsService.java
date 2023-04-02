package com.amryadam.authoriztion_server.services.administration;

import com.amryadam.authoriztion_server.model.administration.SecurityCustomer;
import com.amryadam.authoriztion_server.repository.administration.CustomerRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
@Service
@AllArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return customerRepository.findByName(username)
                .map(SecurityCustomer::new)
                .orElseThrow(()-> new UsernameNotFoundException("Username not found: " + username));
    }
}

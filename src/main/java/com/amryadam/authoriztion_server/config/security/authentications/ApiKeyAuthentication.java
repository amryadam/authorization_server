package com.amryadam.authoriztion_server.config.security.authentications;

import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

@AllArgsConstructor
public class ApiKeyAuthentication implements Authentication {

  private String key;
  private boolean authenticated;

  @Override
  public boolean isAuthenticated() {
    return authenticated;
  }

  @Override
  public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
    this.authenticated = authenticated;
  }

  public String getKey() {
    return key;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return null;
  }

  @Override
  public boolean implies(Subject subject) {
    return Authentication.super.implies(subject);
  }

  @Override
  public String getName() {
    return null;
  }
}

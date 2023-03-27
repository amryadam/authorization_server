//package com.amryadam.sbms.config.security.filters;
//
//
//import com.amryadam.sbms.config.security.authentications.ApiKeyAuthentication;
//import com.amryadam.sbms.config.security.managers.CustomAuthenticationManager;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.AllArgsConstructor;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//
//@AllArgsConstructor
//public class ApiKeyFilter extends OncePerRequestFilter {
//
//  private String key;
//  @Override
//  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//      throws ServletException, IOException {
//
//    var requestKey = request.getHeader("key");
//
//    if (requestKey == null || "null".equals(requestKey)) {
//      filterChain.doFilter(request, response);
//    }
//
//    var auth = new ApiKeyAuthentication(requestKey,false);
//    var manager = new CustomAuthenticationManager(key);
//    try {
//      var a = manager.authenticate(auth);
//      if (a.isAuthenticated()) {
//        SecurityContextHolder.getContext().setAuthentication(a);
//        filterChain.doFilter(request, response);
//      } else {
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//      }
//    } catch (AuthenticationException e) {
//      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//    }
//  }
//}

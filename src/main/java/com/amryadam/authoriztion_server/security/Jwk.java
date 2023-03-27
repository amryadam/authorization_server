package com.amryadam.authoriztion_server.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


@Configuration
public  class Jwk {

//    @Bean
//    public JWKSource<SecurityContext> jwkSource() throws Exception {
//        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
//        kg.initialize(2048);
//        KeyPair kp = kg.generateKeyPair();
//
//        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
//
//        RSAKey key = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        JWKSet set = new JWKSet(key);
//        return new ImmutableJWKSet(set);
//
//
//    }





}

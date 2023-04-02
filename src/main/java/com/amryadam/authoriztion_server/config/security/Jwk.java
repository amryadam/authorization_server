package com.amryadam.authoriztion_server.config.security;

import org.springframework.context.annotation.Configuration;


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

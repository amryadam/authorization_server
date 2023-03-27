package com.amryadam.authoriztion_server.security;

import com.fasterxml.jackson.databind.ser.Serializers;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;



// for pkce code generation
public class PKCE {
    public String Generate(){
        Random random = new Random();
        byte [] code = new byte[32];
        random.nextBytes(code);

        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);

        System.out.println("Verifier = " + verifier );

        try{
            MessageDigest md = MessageDigest.getInstance("SH-256");
            byte[] digested = md.digest(verifier.getBytes());
            var code_challenge = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(digested);
            System.out.println("Challenge = " + code_challenge);

        }catch (Exception ex){

        }
        return "";
    }
}

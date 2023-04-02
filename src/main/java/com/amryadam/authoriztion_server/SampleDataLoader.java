package com.amryadam.authoriztion_server;

import com.amryadam.authoriztion_server.entities.administration.Client;
import com.amryadam.authoriztion_server.services.administration.CustomClientService;


import lombok.AllArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.UUID;



@AllArgsConstructor
@Component
public class SampleDataLoader implements CommandLineRunner {


    private final CustomClientService clientService;
    @Override
    public void run(String... args) throws Exception {
        if (clientService.findByClientId("client") == null){
            var c = new Client(
                    UUID.randomUUID().toString(),
                    "client",
                    "secret",
                    "http://127.0.0.1:4200/admin/authorized",
                    "openid",
                    "client_secret_basic",
                    "authorization_code");
            clientService.save(Client.from(c));
        }

    }
}

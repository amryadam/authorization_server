package com.amryadam.authoriztion_server.services.administration;

import com.amryadam.authoriztion_server.entities.administration.Client;
import com.amryadam.authoriztion_server.repository.administration.ClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
@Transactional
public class CustomClientService implements RegisteredClientRepository {

  private final ClientRepository clientRepository;

  public CustomClientService(ClientRepository clientRepository) {
    this.clientRepository = clientRepository;
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    clientRepository.save(Client.from(registeredClient));
  }

  @Override
  public RegisteredClient findById(String id) {
    var client = clientRepository
            .findById(id)
            .orElseThrow(()->null);
    return Client.from(client);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    return clientRepository
            .findByClientId(clientId)
            .map((c)->Client.from(c))
            .orElse(null);
  }
}

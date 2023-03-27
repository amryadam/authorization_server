package com.amryadam.authoriztion_server.repository.administration;

import com.amryadam.authoriztion_server.entities.administration.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Long> {

    @Query("""
            select c from Client c where c.clientId = :clientId
            """
    )
    Optional<Client> findByClientId(String clientId);

}

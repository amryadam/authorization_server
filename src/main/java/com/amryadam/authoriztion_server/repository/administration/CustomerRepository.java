package com.amryadam.authoriztion_server.repository.administration;

import com.amryadam.authoriztion_server.entities.administration.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface CustomerRepository extends JpaRepository<Customer,String> {

//    @Query("select c.id,c.name,c.password from Customer c where c.name = ?1")
    Optional<Customer> findByName(String name);
}

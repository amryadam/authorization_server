package com.amryadam.authoriztion_server.repository.administration;

import com.amryadam.authoriztion_server.entities.administration.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
public interface UserRepository extends CrudRepository<User,Long> {

    Optional<User> findByUsername(String username);

}

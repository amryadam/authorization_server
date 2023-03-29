package com.amryadam.authoriztion_server.entities.administration;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Entity @Getter @Setter
@AllArgsConstructor
@Table(name = "Customer")
public class Customer {
    @Id
    private String id;
    private String name;
    private String email;
    private String password;
    private String roles;
    public Customer() {

    }
}

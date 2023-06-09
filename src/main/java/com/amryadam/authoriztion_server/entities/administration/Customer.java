package com.amryadam.authoriztion_server.entities.administration;


import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Entity @Getter @Setter
@AllArgsConstructor
@Table(name = "Customer")
public class Customer {
    @Id
    private String id;
    private String code;
    private String name;
    private String email;
    private String password;
    private String roles;
    public Customer() {

    }
}

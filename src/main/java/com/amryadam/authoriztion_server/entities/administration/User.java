package com.amryadam.authoriztion_server.entities.administration;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity @Getter @Setter
@Table(name = "User")
public class User {

    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String roles;

//    @ManyToMany(fetch = FetchType.EAGER)
//    @JoinTable(name = "Users_Authorities",
//            joinColumns = @JoinColumn(name = "user_id"),
//            inverseJoinColumns = @JoinColumn(name = "authority_id")
//    )
//    private Set<Authority> authorities;

    public User() {}

    public User(String username, String password, String roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "SecurityUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", roles='" + roles + '\'' +
                '}';
    }
}

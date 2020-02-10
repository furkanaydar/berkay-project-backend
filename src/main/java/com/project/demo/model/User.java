package com.project.demo.model;


import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
@Getter
@Setter
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public long _id;
    public String username;
    @Size(max = 100)
    public String password;
    public String email;
    public String userRole;




    public User() {
    }



    public User(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }
}
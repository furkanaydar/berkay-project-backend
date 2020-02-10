package com.project.demo.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "authorities")
@Getter
@Setter
public class Authorities {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;

    private String authority;

    @ManyToOne
    @JoinColumn(name="username",referencedColumnName="username")
    private User user;

    public Authorities() {

    }


}

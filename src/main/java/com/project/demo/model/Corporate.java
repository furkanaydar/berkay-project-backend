package com.project.demo.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "corporates")
public class Corporate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long corporateId;

    @NotBlank
    private String corporateName;

    @Column(length = 128, nullable = false)
    @JsonIgnore
    private String encryptedPassword;

    @NotBlank
    private String corporateEmail;


    @ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "corporate_vendors",
            joinColumns = { @JoinColumn(name = "corporate_id") },
            inverseJoinColumns = { @JoinColumn(name = "vendor_id") })
    private Set<Automobile> corporateVendors = new HashSet<>();

    public Corporate() {

    }
    public Corporate(String corporateName, String encryptedPassword, String corporateEmail) {
        this.corporateName = corporateName;
        this.encryptedPassword = encryptedPassword;
        this.corporateEmail = corporateEmail;
    }
}

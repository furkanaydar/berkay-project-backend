package com.project.demo.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.HashSet;
import java.util.Set;


@Getter
@Setter
@Entity
@Table(name = "workers")
public class Worker {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long workerId;

    @NotBlank
    private String workerFirstName;
    @NotBlank
    private String workerLastName;

    @NotBlank
    private String workerUsername;

    @Column(length = 128, nullable = false)
    private String encryptedPassword;


    @Column(length = 128, nullable = false)
    private String phoneNumber;

    private int numberOfAssignedCars;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "corporate_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    private Corporate corporate;


    public Worker() {
        this.numberOfAssignedCars = 0;
    }
}

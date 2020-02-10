package com.project.demo.model;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.*;

@Getter
@Setter
@Entity
@Table(name = "automobiles_workers")
public class AutomobileOfWorker {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long automobileOfWorkerId;
    @ManyToOne
    @JoinColumn(name = "automobile_id")
    @OnDelete(action = OnDeleteAction.CASCADE)

    Automobile automobile;

    @ManyToOne
    @JoinColumn(name = "worker_id")
    @OnDelete(action = OnDeleteAction.CASCADE)

    Worker worker;

    public AutomobileOfWorker(Automobile automobile, Worker worker) {
        this.automobile = automobile;
        this.worker = worker;
    }
    public AutomobileOfWorker() {

    }
}

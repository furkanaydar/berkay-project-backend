package com.project.demo.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.*;

@Entity
@Getter
@Setter
@Table(name = "requests")
public class Request {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long requestId;
    @ManyToOne
    @JoinColumn(name = "corporate_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore

    Corporate corporate;

    @ManyToOne
    @JoinColumn(name = "worker_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    //@JsonIgnore

    Worker worker;

    @ManyToOne
    @JoinColumn(name = "vendor_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    Vendor vendor;

    @ManyToOne
    @JoinColumn(name = "automobile_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    Automobile automobile;

    private double vendorLat;
    private double vendorLong;

    public boolean result;

    // KAREKOD

    public Request() {

    }

    public Request(Corporate corporate, Worker worker, Vendor vendor) {
        this.corporate = corporate;
        this.worker = worker;
        this.vendor = vendor;
    }
}

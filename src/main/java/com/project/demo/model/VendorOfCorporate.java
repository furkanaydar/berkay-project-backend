package com.project.demo.model;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import javax.persistence.*;

@Table(name = "vendor_corporate")
@Entity
@Getter
@Setter
public class VendorOfCorporate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long vendorOfCorporateId;
    @ManyToOne
    @JoinColumn(name = "corporate_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    Corporate corporate;

    @ManyToOne
    @JoinColumn(name = "vendor_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    Vendor vendor;

    public VendorOfCorporate() {

    }

    public VendorOfCorporate(Corporate corporate, Vendor vendor) {
        this.corporate = corporate;
        this.vendor = vendor;
    }
}

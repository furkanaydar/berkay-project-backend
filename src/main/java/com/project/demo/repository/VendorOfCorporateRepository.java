package com.project.demo.repository;

import com.project.demo.model.*;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface VendorOfCorporateRepository extends JpaRepository<VendorOfCorporate, Long> {
    List<VendorOfCorporate> findVendorOfCorporatesByCorporate(Corporate corporate);
    List<VendorOfCorporate> findVendorOfCorporatesByVendor(Vendor vendor);
    List<VendorOfCorporate> findVendorOfCorporatesByCorporateAndVendor(Corporate corporate, Vendor vendor);
}


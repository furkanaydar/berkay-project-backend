package com.project.demo.repository;

import com.project.demo.model.Corporate;
import com.project.demo.model.Vendor;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface VendorRepository extends JpaRepository<Vendor, Long> {
    List<Vendor> findVendorsByCorporatesContains(Corporate corporate);
}

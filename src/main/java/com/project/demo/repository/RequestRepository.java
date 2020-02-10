package com.project.demo.repository;

import com.project.demo.model.Corporate;
import com.project.demo.model.Request;
import com.project.demo.model.Vendor;
import com.project.demo.model.Worker;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RequestRepository extends JpaRepository<Request, Long> {
    List<Request> findRequestsByCorporate(Corporate corporate);
    List<Request> findRequestsByWorker(Worker worker);
    List<Request> findRequestsByCorporateAndVendor(Corporate corporate, Vendor vendor);
}

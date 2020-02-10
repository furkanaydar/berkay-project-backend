package com.project.demo.repository;

import com.project.demo.model.Corporate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CorporateRepository extends JpaRepository<Corporate, Long> {
    Corporate findCorporateByCorporateEmail(String corporateEmail);
    Corporate findCorporateByCorporateName(String corporateName);
    Corporate findCorporateByCorporateId(Long corporateId);

}

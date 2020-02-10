package com.project.demo.repository;

import com.project.demo.model.Automobile;
import com.project.demo.model.Corporate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AutomobileRepository extends JpaRepository<Automobile, Long> {
    List<Automobile> findAutomobilesByCorporate(Corporate corporate);
    Automobile findAutomobileByAutomobileId(Long automobileId);
    Automobile findAutomobileByAutomobileLicensePlate(String licensePlate);
}

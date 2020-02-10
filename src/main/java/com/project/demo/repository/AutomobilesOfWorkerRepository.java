package com.project.demo.repository;

import com.project.demo.model.Automobile;
import com.project.demo.model.AutomobileOfWorker;
import com.project.demo.model.Worker;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AutomobilesOfWorkerRepository extends JpaRepository<AutomobileOfWorker, Long> {
    List<AutomobileOfWorker> findAutomobileOfWorkersByWorker(Worker worker);
    List<AutomobileOfWorker> findAutomobileOfWorkersByAutomobile(Automobile automobile);
    List<AutomobileOfWorker> findAutomobileOfWorkersByAutomobileAndWorker(Automobile automobile, Worker worker);
    boolean existsAutomobileOfWorkerByAutomobileAndWorker(Automobile automobile, Worker worker);
}


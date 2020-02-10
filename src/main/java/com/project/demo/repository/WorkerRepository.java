package com.project.demo.repository;

import com.project.demo.model.Corporate;
import com.project.demo.model.Worker;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface WorkerRepository extends JpaRepository<Worker, Long> {
    List<Worker> findWorkersByCorporate(Corporate corporate);
    Worker findWorkerByWorkerId(Long workerId);
}

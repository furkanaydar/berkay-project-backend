package com.project.demo.controller;

import com.project.demo.model.Automobile;
import com.project.demo.model.Corporate;
import com.project.demo.model.Worker;
import com.project.demo.repository.AutomobileRepository;
import com.project.demo.repository.CorporateRepository;
import com.project.demo.repository.WorkerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
public class WorkerController {

    @Autowired
    private CorporateRepository corporateRepository;

    @Autowired
    private AutomobileRepository automobileRepository;

    @Autowired
    private WorkerRepository workerRepository;


    @RequestMapping(value = "/workers/{workerId}", method = RequestMethod.DELETE)
    public ResponseEntity<Object> getCorporate(@PathVariable("workerId") Long workerId) {
        Worker worker = workerRepository.findWorkerByWorkerId(workerId);
        workerRepository.delete(worker);
        return new ResponseEntity<Object>(worker, HttpStatus.OK);
    }
}

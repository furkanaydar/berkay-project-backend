package com.project.demo.controller;

import com.google.gson.JsonObject;
import com.google.maps.errors.ApiException;
import com.project.demo.dto.RegisterCredentialsWorker;
import com.project.demo.dto.WorkerIdWrapper;
import com.project.demo.model.*;
import com.project.demo.repository.*;
import com.project.demo.service.UserService;
import com.project.demo.service.impl.GeocodeApiServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class CorporateController {

    @Autowired
    private CorporateRepository corporateRepository;

    @Autowired
    private AutomobileRepository automobileRepository;

    @Autowired
    private WorkerRepository workerRepository;

    @Autowired
    private AutomobilesOfWorkerRepository automobilesOfWorkerRepository;

    @Autowired
    private VendorRepository vendorRepository;

    @Autowired
    private VendorOfCorporateRepository vendorOfCorporateRepository;

    @Autowired
    private GeocodeApiServiceImpl geocodeApiService;

    @Autowired
    private RequestRepository requestRepository;

    private final PasswordEncoder passwordEncoder;

    private final UserService userService;

    public CorporateController(UserService userService, PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }


    @RequestMapping(value = "/corporates", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Corporate> createCorporate(@RequestBody Corporate corporate) {

        corporateRepository.save(corporate);
        return new ResponseEntity<Corporate>(corporate, HttpStatus.OK);
    }

    @RequestMapping(value = "/corporates/{corporateId}", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Corporate> getCorporate(@PathVariable("corporateId") Long corporateId) {
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        return new ResponseEntity<Corporate>(corporate, HttpStatus.OK);
    }

    @RequestMapping(value = "/corporates/{corporateId}/automobiles", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Automobile> getAutomobilesOfCorporate(@PathVariable("corporateId") Long corporateId) {
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        return automobileRepository.findAutomobilesByCorporate(corporate);
    }

    @RequestMapping(value = "/corporates/{corporateId}/automobiles/{automobileId}", method = RequestMethod.DELETE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> deleteAutomobileOfCorporate(
            @PathVariable("corporateId") Long corporateId,
            @PathVariable("automobileId") Long automobileId) {
        Automobile automobile = automobileRepository.findAutomobileByAutomobileId(automobileId);
        List<AutomobileOfWorker> automobileOfWorkers = automobilesOfWorkerRepository.findAutomobileOfWorkersByAutomobile(automobile);
        for(int i=0 ; i<automobileOfWorkers.size() ; i++) {
            Worker worker = automobileOfWorkers.get(i).getWorker();
            int currentNumberOfAutos = worker.getNumberOfAssignedCars();
            worker.setNumberOfAssignedCars(currentNumberOfAutos - 1);
            workerRepository.save(worker);
        }
        automobileRepository.delete(automobile);
        return new ResponseEntity<Object>(automobile, HttpStatus.OK);
    }

    @RequestMapping(value = "/corporates/{corporateId}/automobiles",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Automobile> createAutomobileForCorporate(
            @PathVariable("corporateId") Long corporateId,
            @RequestBody Automobile automobile) {
        Corporate linkedCorporate = corporateRepository.findCorporateByCorporateId(corporateId);
        automobile.setCorporate(linkedCorporate);
        automobileRepository.save(automobile);
        return new ResponseEntity<Automobile>(automobile, HttpStatus.OK);
    }

    @RequestMapping(value = "/corporates/{corporateId}/workers", method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Worker> getWorkersOfCorporate(@PathVariable("corporateId") Long corporateId) {
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        return workerRepository.findWorkersByCorporate(corporate);
    }

    @RequestMapping(value = "/corporates/{corporateId}/workers", method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Worker> createWorkerForCorporate(
            @PathVariable("corporateId") Long corporateId,
            @RequestBody RegisterCredentialsWorker registerCredentialsWorker) {
        Worker worker = new Worker();
        worker.setWorkerUsername(registerCredentialsWorker.getUsername());
        worker.setEncryptedPassword(passwordEncoder.encode(registerCredentialsWorker.getPassword()));
        worker.setPhoneNumber(registerCredentialsWorker.getPhoneNumber());
        worker.setWorkerFirstName(registerCredentialsWorker.getWorkerFirstName());
        worker.setWorkerLastName(registerCredentialsWorker.getWorkerLastName());
        Corporate linkedCorporate = corporateRepository.findCorporateByCorporateId(corporateId);

        worker.setCorporate(linkedCorporate);
        workerRepository.save(worker);

        User user = new User(registerCredentialsWorker.getUsername(),
                passwordEncoder.encode(registerCredentialsWorker.getPassword()),
                registerCredentialsWorker.getEmail());
        if (registerCredentialsWorker.getUserRole() == null) {
            user.setUserRole("none");
        } else {
            user.setUserRole(registerCredentialsWorker.getUserRole());
        }

        userService.saveUser(user);

        return new ResponseEntity<Worker>(worker, HttpStatus.OK);
    }

    @RequestMapping(value = "/corporates/{corporateId}/automobiles/{automobileId}/assignedWorkers",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AutomobileOfWorker> getWorkersForAutomobile(
            @PathVariable("corporateId") Long corporateId,
            @PathVariable("automobileId") Long automobileId) {
        Automobile automobile = automobileRepository.findAutomobileByAutomobileId(automobileId);
        return automobilesOfWorkerRepository.findAutomobileOfWorkersByAutomobile(automobile);
    }

    @RequestMapping(value = "/corporates/{corporateId}/workers/{workerId}/assignedVehicles",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AutomobileOfWorker> getAutomobilesForWorker(
            @PathVariable("corporateId") Long corporateId,
            @PathVariable("workerId") Long workerId) {
        Worker worker = workerRepository.findWorkerByWorkerId(workerId);
        return automobilesOfWorkerRepository.findAutomobileOfWorkersByWorker(worker);
    }



    @RequestMapping(value = "/corporates/{corporateId}/automobiles/{automobileId}/assignedWorkers",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createWorkerForAutomobile(
            @PathVariable("corporateId") Long corporateId,
            @PathVariable("automobileId") Long automobileId,
            @RequestBody WorkerIdWrapper workerIdWrapper) {
        System.out.println(corporateId + " " + automobileId + " "+ workerIdWrapper.getWorkerId());

        Automobile automobile = automobileRepository.findAutomobileByAutomobileId(automobileId);

        Worker worker = workerRepository.findWorkerByWorkerId(workerIdWrapper.getWorkerId());
        if(automobilesOfWorkerRepository.findAutomobileOfWorkersByAutomobileAndWorker(automobile, worker).size() > 0) {
            return new ResponseEntity<Object>("already assigned.", HttpStatus.OK);
        }
        int currentAssignedCarNumber = worker.getNumberOfAssignedCars();
        worker.setNumberOfAssignedCars(currentAssignedCarNumber + 1);
        AutomobileOfWorker automobileOfWorker = new AutomobileOfWorker(automobile, worker);
        automobilesOfWorkerRepository.save(automobileOfWorker);
        return new ResponseEntity<Object>("success", HttpStatus.OK);

    }

    @RequestMapping(value = "/corporates/{corporateId}/vendors",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<VendorOfCorporate> getVendorsForCorporate(
            @PathVariable("corporateId") Long corporateId) {
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        return vendorOfCorporateRepository.findVendorOfCorporatesByCorporate(corporate);
    }

    @RequestMapping(value = "/corporates/{corporateId}/vendors",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public void createVendorForCorporate(
            @PathVariable("corporateId") Long corporateId,
            @RequestBody Vendor vendor) throws InterruptedException, ApiException, IOException {
        List<String> result = geocodeApiService.generate(vendor.getVendorAddress());
        vendor.setVendorLat(Double.parseDouble(result.get(0)));
        vendor.setVendorLong(Double.parseDouble(result.get(1)));
        vendorRepository.save(vendor);
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        VendorOfCorporate vendorOfCorporate = new VendorOfCorporate(corporate, vendor);
        vendorOfCorporateRepository.save(vendorOfCorporate);
    }

    @RequestMapping(value = "/corporates/{corporateId}/requests",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getRequestsOfCorporate(
            @PathVariable("corporateId") Long corporateId
            ) {
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        List<Request> requests = requestRepository.findRequestsByCorporate(corporate);
        return new ResponseEntity<Object>(requests, HttpStatus.OK);
    }

    @RequestMapping(value = "/vehicles/{vehicleLicensePlate}/requests",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> registerRequestLessParams(
            @PathVariable("vehicleLicensePlate") String vehicleLicensePlate,
            @RequestBody Request request
    ) {
        String username = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            username = ((UserDetails)principal).getUsername();
        } else {
            username = principal.toString();
        }
        if(null == username || username.length() == 0) {
            return new ResponseEntity<Object>(HttpStatus.BAD_REQUEST);
        }
        Worker worker = workerRepository.findWorkerByWorkerUsername(username);
        if(null == worker) {
            return new ResponseEntity<Object>(HttpStatus.BAD_REQUEST);
        }
        Corporate corporate = worker.getCorporate();
        Long corporateId = corporate.getCorporateId();
        Automobile automobile = automobileRepository.findAutomobileByAutomobileLicensePlate(vehicleLicensePlate);
        if(automobile == null || automobile.getCorporate().getCorporateId() != corporateId) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "unknown vehicle");
            return new ResponseEntity<Object>(HttpStatus.BAD_REQUEST);
        }
        if(!automobilesOfWorkerRepository.existsAutomobileOfWorkerByAutomobileAndWorker(automobile, worker)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Vehicle is not assigned for the worker.");
            return new ResponseEntity<Object>(HttpStatus.BAD_REQUEST);
        }

        Vendor closestVendor = geocodeApiService.findClosestVendor(corporate, request.getVendorLat(), request.getVendorLong());
        if(closestVendor != null) {
            request.setCorporate(corporate);
            request.setWorker(worker);
            request.setAutomobile(automobile);
            request.setVendor(closestVendor);
            request.setResult(true);
            requestRepository.save(request);
            return new ResponseEntity<Object>(request, HttpStatus.OK);
        }
        request.setCorporate(corporate);
        request.setWorker(worker);
        request.setAutomobile(automobile);
        request.setVendor(null);
        request.setResult(false);
        requestRepository.save(request);
        Map<String, Object> body = new HashMap<>();
        body.put("error", "Your location does not match of any known stations.");
        return new ResponseEntity<Object>(body, HttpStatus.BAD_REQUEST);
    }

    @RequestMapping(value = "/corporates/{corporateId}/workers/{workerId}/vehicles/{vehicleLicensePlate}/requests",
                    method = RequestMethod.POST,
                    consumes = MediaType.APPLICATION_JSON_VALUE,
                    produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> registerRequest(
            @PathVariable("corporateId") Long corporateId,
            @PathVariable("workerId") Long workerId,
            @PathVariable("vehicleLicensePlate") String vehicleLicensePlate,
            @RequestBody Request request
            ) {
        Worker worker = workerRepository.findWorkerByWorkerId(workerId);
        Corporate corporate = corporateRepository.findCorporateByCorporateId(corporateId);
        Automobile automobile = automobileRepository.findAutomobileByAutomobileLicensePlate(vehicleLicensePlate);
        if(automobile == null || automobile.getCorporate().getCorporateId() != corporateId) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "unknown vehicle");
            return new ResponseEntity<Object>(body, HttpStatus.OK);
        }
        if(!automobilesOfWorkerRepository.existsAutomobileOfWorkerByAutomobileAndWorker(automobile, worker)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Vehicle is not assigned for the worker.");
            return new ResponseEntity<Object>(body, HttpStatus.OK);
        }

        Vendor closestVendor = geocodeApiService.findClosestVendor(corporate, request.getVendorLat(), request.getVendorLong());
        if(closestVendor != null) {
            request.setCorporate(corporate);
            request.setWorker(worker);
            request.setAutomobile(automobile);
            request.setVendor(closestVendor);
            request.setResult(true);
            requestRepository.save(request);
            return new ResponseEntity<Object>(request, HttpStatus.OK);
        }
        request.setCorporate(corporate);
        request.setWorker(worker);
        request.setAutomobile(automobile);
        request.setVendor(null);
        request.setResult(false);
        requestRepository.save(request);
        Map<String, Object> body = new HashMap<>();
        body.put("error", "Your location does not match of any known stations.");
        return new ResponseEntity<Object>(body, HttpStatus.OK);
    }
}

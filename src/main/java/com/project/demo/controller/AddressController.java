package com.project.demo.controller;

import com.google.maps.errors.ApiException;
import com.project.demo.model.Corporate;
import com.project.demo.model.VendorOfCorporate;
import com.project.demo.service.impl.GeocodeApiServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
public class AddressController {
    @Autowired
    private GeocodeApiServiceImpl geocodeApiService;

    @RequestMapping(value = "/coordinates",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<String> getLatLong(
            @RequestBody String address) throws InterruptedException, ApiException, IOException {
        return geocodeApiService.generate(address);
    }

}

package com.project.demo.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.maps.GeoApiContext;
import com.google.maps.GeocodingApi;
import com.google.maps.errors.ApiException;
import com.google.maps.model.GeocodingResult;
import com.project.demo.model.Corporate;
import com.project.demo.model.Vendor;
import com.project.demo.model.VendorOfCorporate;
import com.project.demo.repository.VendorOfCorporateRepository;
import com.project.demo.repository.VendorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class GeocodeApiServiceImpl {

    @Autowired
    private VendorOfCorporateRepository vendorOfCorporateRepository;
    @Autowired
    private VendorRepository vendorRepository;

    private GeoApiContext context;


   public GeocodeApiServiceImpl() {
       this.context = new GeoApiContext.Builder().apiKey("AIzaSyAmI5eCvq_mpHjjljZ6XfVdGoyX1mtZ51A").build();
   }

   public List<String> generate(String address) throws InterruptedException, ApiException, IOException {
       GeocodingResult[] results = GeocodingApi.geocode(context, address).await();
       Gson gson = new GsonBuilder().setPrettyPrinting().create();
       String _lat = gson.toJson(results[0].geometry.location.lat);
       String _long = gson.toJson(results[0].geometry.location.lng);
       List<String> result = new ArrayList<>();
       result.add(_lat);
       result.add(_long);
       return result;
   }

   public double distance(double lat1, double lon1, double lat2, double lon2) {
       double pi = 0.017453292519943295;
       double a = 0.5 - Math.cos((lat2 - lat1) * pi) /2 +
               Math.cos(lat1 * pi) * Math.cos(lat2 * pi) *
                       (1 - Math.cos((lon2 - lon1) * pi)) / 2;
       return 12742 * Math.asin(Math.sqrt(a));
   }

   public Vendor findClosestVendor(Corporate corporate, double lat, double lng) {
       double maxDist = 2100000000;
       Vendor closestVendor = new Vendor();
       List<VendorOfCorporate> vendorOfCorporates =
               vendorOfCorporateRepository.findVendorOfCorporatesByCorporate(corporate);
       List<Vendor> vendors = new ArrayList<>();
       for(final VendorOfCorporate vendorOfCorporate: vendorOfCorporates) {
           vendors.add(vendorOfCorporate.getVendor());
       }
       for(final Vendor vendor: vendors) {
           double currentLat = vendor.getVendorLat();
           double currentLng = vendor.getVendorLong();
           double currentDist = distance(lat, lng, currentLat, currentLng);
           if(currentDist < maxDist) {
               maxDist = currentDist;
               closestVendor = vendor;
           }
       }
       if(maxDist < 1) {
           return closestVendor;
       }
       return null;
   }
}

package com.satdata.bdsat.Controllers;
import com.satdata.bdsat.service.AuthService;
import org.apache.commons.io.FileUtils;
import org.apache.commons.ssl.PKCS8Key;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@RestController
public class AuthController {
    private String SOAPXML = "";
    @Autowired
    private AuthService authService;


    @PostMapping("/upload")
    public String[] handleFileUpload(@RequestParam("certificateMF") MultipartFile certificateMF, @RequestParam("keyMF") MultipartFile keyMF, @RequestParam("key") String key) {
        SOAPXML =this.authService.createSoapRequest(certificateMF, keyMF, key);
        String response = this.authService.sendSoapRequest(SOAPXML);
        System.out.println(SOAPXML);
        String[] responseToSend = {SOAPXML};
        return responseToSend;
    }

}

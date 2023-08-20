package com.satdata.bdsat.service;


import org.springframework.web.multipart.MultipartFile;

public interface AuthService {

    String createSoapRequest(MultipartFile certificateMF, MultipartFile keyMF, String key);
    String sendSoapRequest(String soapreq);



}

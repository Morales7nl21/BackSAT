package com.satdata.bdsat.serviceimp;

import com.satdata.bdsat.service.AuthService;
import com.satdata.bdsat.utils.AuthUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service

public class AuthServiceImp implements AuthService {

    public final String URIAUTHENTICATION = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc?singleWsdl";
    public static String PATH = "C:/Users/Rodrigo/OneDrive - Instituto Politecnico Nacional/Desktop/RetoInge/files/";
    @Autowired
    private AuthUtils authUtils;

    public String createSoapRequest(MultipartFile certificateMF,  MultipartFile keyMF,  String key) {
        String fileName = certificateMF.getOriginalFilename();
        String fileNameKey = keyMF.getOriginalFilename();
        String fileNameCertificate = certificateMF.getOriginalFilename();
        try {
            certificateMF.transferTo( new File(PATH+fileName));
            keyMF.transferTo( new File(PATH+fileNameKey));
            File filekeycipher = new File(PATH+keyMF.getOriginalFilename());
            byte[] bytes = Files.readAllBytes(Paths.get(PATH+fileName));
            String encodedString = Base64.getEncoder().encodeToString(bytes);
            Instant instant = Instant.now();
            Instant instant2 = instant.plus(5, ChronoUnit.MINUTES);

            String created = instant.toString();
            String expires = instant2.toString();
            UUID uuid = UUID.randomUUID();

            String canonicalTimeStamp = "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\">" +
                    "<u:Created>" + created + "</u:Created>" +
                    "<u:Expires>" + expires + "</u:Expires>" +
                    "</u:Timestamp>";

            String digest = this.authUtils.CreateDigest(canonicalTimeStamp);

            String canonicalSignedInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod>" +
                    "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>" +
                    "<Reference URI=\"#_0\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>" +
                    "<DigestValue>" + digest + "</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>";

            PrivateKey keyToSignature = this.authUtils.getPrivateKey(filekeycipher,key);
            String signature = this.authUtils.Sign(canonicalSignedInfo,keyToSignature);
            String certificateBase64 = Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get(PATH+fileNameCertificate)));
            char tr  = 34;
            String soap_request = "<s:Envelope xmlns:s="+ String.valueOf(tr) +"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
                    "<s:Header>" +
                    "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" +
                    "<u:Timestamp u:Id=\"_0\">" +
                    "<u:Created>" + created + "</u:Created>" +
                    "<u:Expires>" + expires + "</u:Expires>" +
                    "</u:Timestamp>" +
                    "<o:BinarySecurityToken u:Id=\"" + uuid
                    + "\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" +
                    certificateBase64 +
                    "</o:BinarySecurityToken>" +
                    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<SignedInfo>" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
                    "<Reference URI=\"#_0\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>" + digest + "</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>" +
                    "<SignatureValue>" + signature + "</SignatureValue>" +
                    "<KeyInfo>" +
                    "<o:SecurityTokenReference>" +
                    "<o:Reference ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" URI=\"#" + uuid + "\"/>" +
                    "</o:SecurityTokenReference>" +
                    "</KeyInfo>" +
                    "</Signature>" +
                    "</o:Security>" +
                    "</s:Header>" +
                    "<s:Body>" +
                    "<Autentica xmlns=\"http://DescargaMasivaTerceros.gob.mx\"/>" +
                    "</s:Body>" + "</s:Envelope>";


            soap_request= soap_request.replaceAll("\\\\","" );
           // System.out.println(soap_request);
            return soap_request;
        } catch (Exception e) {
            System.out.println(e);
            return e.toString();
        }
    }

    @Override
    public String sendSoapRequest(String soapreq) {
        try {
            URL url = new URL("https://consultaqr.facturaelectronica.sat.gob.mx/consultacfdiservice.svc?wsdl");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("Accept-Encoding", "gzip");
            connection.setRequestProperty("SOAPAction", "\"http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica\"");
            connection.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

            connection.setRequestMethod("POST");
            connection.setDoOutput(true); // Permite Escritura
            connection.setDoInput(true);
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(soapreq.getBytes());
            os.flush();
            os.close();

            String responseMessage = connection.getResponseMessage();
            int responseCode = connection.getResponseCode();
            System.out.println("POST Response Code :: " + responseCode);
            System.out.println(responseMessage);
            if (responseCode == HttpURLConnection.HTTP_OK) { //success
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                return response.toString();
            } else {
                return ("POST request did not work." + responseMessage);
            }
        } catch (MalformedURLException | ProtocolException ex) {
            return ("Exception" + ex);
        } catch (IOException e) {
            return (e.toString());
        }
    }
}

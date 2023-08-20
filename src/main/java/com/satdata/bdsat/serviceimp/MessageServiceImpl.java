package com.satdata.bdsat.serviceimp;
/*
import org.bouncycastle.crypto.generators.BCrypt;

import java.security.KeyPair;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.cryptacular.*;

public class MessageServiceImpl {

    private String RFCSOLICITANTE;
    private String RFCRECEPTOR;
    private String RFCEMISOR;
    private String INICIO;
    private String FIN;
    private String TIPO;
    private String SHADIGESTB64;
    private KeyPair KEYPAIR;
    private String SELLOB64;
    private byte[] BYTECER;

    public SOAPMessage getSOAPMessageSolicitud(
            byte[] byteCer,
            byte[] byteKey,
            byte[] byteClave,
            String token,
            String rfcEmisor,
            String rfcReceptor,
            String rfcSolicitante,
            Date fechaInicial,
            Date fechaFinal,
            String tipoSolicitud,
            String urlSolicitudAction
    ) {
        SOAPMessage soapMessage = null;
        this.RFCEMISOR = rfcEmisor;
        this.RFCSOLICITANTE = rfcSolicitante;
        this.RFCRECEPTOR = rfcReceptor;
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        this.INICIO = format.format(fechaInicial);
        this.FIN = format.format(fechaFinal);
        this.TIPO = tipoSolicitud;
        this.BYTECER = byteCer;
        try {
            BCrypt
            this.KEYPAIR = KeyPairUtil.keyPair(byteCer, byteKey, byteClave);
            MessageFactory messageFactory = MessageFactory.newInstance(
                    SOAPConstants.DEFAULT_SOAP_PROTOCOL
            );
            soapMessage = messageFactory.createMessage();
            //*************************************************
            //parte o sección del mensaje
            SOAPPart soapPart = soapMessage.getSOAPPart();
            //sobre del mensaje, que es una parte del mismo
            SOAPEnvelope soapEnvelope = soapPart.getEnvelope();

            //MODIFICANDO EL ENVELOPE
            //obtenemos el prefijo actual SOAP-ENV
            String prefijo = soapEnvelope.getPrefix();
            //quitamos el espacio con nombre del prefijo actual
            soapEnvelope.removeNamespaceDeclaration(prefijo);
            //colocamos el prefijo que deseamos s, si no agregamos este prefijo usará el default que es SOAP-ENV
            soapEnvelope.setPrefix("s");
            //agregamos el nombre de espacio para el prefijo s
            soapEnvelope.addNamespaceDeclaration(
                    "s",
                    "http://schemas.xmlsoap.org/soap/envelope/"
            );
            //espacio con nombre para la seguridad
            // soapEnvelope.addNamespaceDeclaration("u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            // soapEnvelope.addNamespaceDeclaration("des", "http://DescargaMasivaTerceros.sat.gob.mx"); //xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"
            // soapEnvelope.addNamespaceDeclaration("xd", "http://www.w3.org/2000/09/xmldsig#"); //xmlns:xd="http://www.w3.org/2000/09/xmldsig#"

            //HEADER
            this.agregarHeader(soapEnvelope);
            //BODY
            this.agregarBody(soapEnvelope);

            javax.xml.soap.MimeHeaders headers = null;
            headers = soapMessage.getMimeHeaders();
            headers.addHeader("Authorization", token);
            headers.addHeader("soapAction", urlSolicitudAction);

            soapMessage.saveChanges();
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el mensaje SOAP Solicitud",
                    exc
            );
        }
        return soapMessage;
    }

    //HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER
    private void agregarHeader(SOAPEnvelope soapEnvelope) {
        try {
            //obtenemos el Header que por default se asi:
            //<SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"/>
            SOAPHeader soapHeader = soapEnvelope.getHeader();
            //obtenemos el prefijo default SOAP-ENV
            String prefijo = soapHeader.getPrefix();
            soapHeader.removeNamespaceDeclaration(prefijo);
            //asignamos el prefijo S
            soapHeader.setPrefix("s");

            SOAPHeaderElement soapHeaderElementActivityId = soapHeader.addHeaderElement(
                    new QName(
                            "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
                            "ActivityId",
                            ""
                    )
            );
            this.agregarHeader_ActivityId(soapHeaderElementActivityId);
        } catch (SOAPException exc) {
            throw new RuntimeException("Error al crear el nodo Header", exc);
        }
    }

    private void agregarHeader_ActivityId(
            SOAPHeaderElement soapHeaderElementActivityId
    ) {
        try {
            soapHeaderElementActivityId.setAttribute(
                    "CorrelationId",
                    "806aad0d-ef46-443b-9741-040c8e8e8c7d"
            );
            //soapHeaderElementActivityId.setAttribute("xmlns", "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics");
            soapHeaderElementActivityId.addTextNode(
                    "e906cfb4-f706-43de-94d0-5cc935be1aaa"
            );
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el nodo Header - ActivityId",
                    exc
            );
        }
    }

    //HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER HEADER

    //BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY BODY
    private void agregarBody(SOAPEnvelope soapEnvelope) {
        try {
            SOAPBody soapBody = soapEnvelope.getBody();
            String prefijo = soapBody.getPrefix();
            soapBody.removeNamespaceDeclaration(prefijo);
            soapBody.setPrefix("s");
            soapBody.addNamespaceDeclaration(
                    "xsi",
                    "http://www.w3.org/2001/XMLSchema-instance"
            );
            soapBody.addNamespaceDeclaration(
                    "xsd",
                    "http://www.w3.org/2001/XMLSchema"
            );

            this.agregarBody_SolicitaDescarga(soapBody, soapEnvelope);
        } catch (SOAPException exc) {
            throw new RuntimeException("Error al crear el nodo Body", exc);
        }
    }

    private void agregarBody_SolicitaDescarga(
            SOAPBody soapBody,
            SOAPEnvelope soapEnvelope
    ) {
        try {
            //aquí al crear el nodo se agrega el nombre, el prefijo y su espacio con nombre
            SOAPElement soapElementSolicitaDescarga = soapBody.addBodyElement(
                    soapEnvelope.createName(
                            "SolicitaDescarga",
                            "",
                            "http://DescargaMasivaTerceros.sat.gob.mx"
                    )
            );

            this.agregarBody_SolicitaDescarga_solicitud(soapElementSolicitaDescarga);
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el nodo Body - SolicitaDescarga",
                    exc
            );
        }
    }

    private void agregarBody_SolicitaDescarga_solicitud(
            SOAPElement soapElementSolicitaDescarga
    ) {
        try {
            //aquí al crear el nodo se agrega el nombre, el prefijo y su espacio con nombre
            SOAPElement soapElementSolicitaDescargaSolicitud = soapElementSolicitaDescarga.addChildElement(
                    "solicitud"
            );
            if (this.RFCEMISOR != null) {
                soapElementSolicitaDescargaSolicitud.setAttribute(
                        "RfcEmisor",
                        this.RFCEMISOR
                );
            }

            soapElementSolicitaDescargaSolicitud.setAttribute(
                    "RfcSolicitante",
                    this.RFCSOLICITANTE
            );
            soapElementSolicitaDescargaSolicitud.setAttribute(
                    "FechaInicial",
                    this.INICIO
            );
            soapElementSolicitaDescargaSolicitud.setAttribute("FechaFinal", this.FIN);
            soapElementSolicitaDescargaSolicitud.setAttribute(
                    "TipoSolicitud",
                    this.TIPO
            );

            if (this.RFCRECEPTOR != null) {
                this.agregarBody_SolicitaDescarga_solicitud_Receptores(
                        soapElementSolicitaDescargaSolicitud
                );
            }

            this.agregarBody_SolicitaDescarga_solicitud_Signature(
                    soapElementSolicitaDescargaSolicitud
            );
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el nodo Body - SolicitaDescarga - solicitud",
                    exc
            );
        }
    }

    private void agregarBody_SolicitaDescarga_solicitud_Receptores(
            SOAPElement soapElementSolicitaDescargaSolicitud
    ) {
        try {
            SOAPElement soapElementSolicitaDescargaSolicitudRfcReceptores = soapElementSolicitaDescargaSolicitud.addChildElement(
                    "RfcReceptores"
            );
            SOAPElement soapElementSolicitaDescargaSolicitudRfcReceptoresReceptor = soapElementSolicitaDescargaSolicitudRfcReceptores.addChildElement(
                    "RfcReceptor"
            );

            soapElementSolicitaDescargaSolicitudRfcReceptoresReceptor.setTextContent(
                    RFCRECEPTOR
            );
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el nodo Body - SolicitaDescarga - solicitud - RfcReceptores",
                    exc
            );
        }
    }

    private void agregarBody_SolicitaDescarga_solicitud_Signature(
            SOAPElement soapElementSolicitaDescargaSolicitud
    ) {
        try {
            SOAPElement soapElementSolicitaDescargaSolicitudSignature = soapElementSolicitaDescargaSolicitud.addChildElement(
                    "Signature",
                    "",
                    "http://www.w3.org/2000/09/xmldsig#"
            );
            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfo = soapElementSolicitaDescargaSolicitudSignature.addChildElement(
                    "SignedInfo"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoCanonicalizationMethod = soapElementSolicitaDescargaSolicitudSignatureSignedInfo.addChildElement(
                    "CanonicalizationMethod"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoCanonicalizationMethod.setAttribute(
                    "Algorithm",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoSignatureMethod = soapElementSolicitaDescargaSolicitudSignatureSignedInfo.addChildElement(
                    "SignatureMethod"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoSignatureMethod.setAttribute(
                    "Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoReference = soapElementSolicitaDescargaSolicitudSignatureSignedInfo.addChildElement(
                    "Reference"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoReference.setAttribute(
                    "URI",
                    "#_0"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceTransforms = soapElementSolicitaDescargaSolicitudSignatureSignedInfoReference.addChildElement(
                    "Transforms"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceTransformsTransform = soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceTransforms.addChildElement(
                    "Transform"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceTransformsTransform.setAttribute(
                    "Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceDigestMethod = soapElementSolicitaDescargaSolicitudSignatureSignedInfoReference.addChildElement(
                    "DigestMethod"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceDigestMethod.setAttribute(
                    "Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#sha1"
            );

            String canonicalTimestamp = this.getCanonicalTimestamp();
            byte[] byteSha1 = Sha.sha1(canonicalTimestamp);
            this.SHADIGESTB64 = Base64.getEncoder().encodeToString(byteSha1);

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceDigestValue = soapElementSolicitaDescargaSolicitudSignatureSignedInfoReference.addChildElement(
                    "DigestValue"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignedInfoReferenceDigestValue.addTextNode(
                    this.SHADIGESTB64
            );

            String canonicalSignedInfo =
                    this.getCanonicalSignedInfo(this.SHADIGESTB64);
            this.SELLOB64 =
                    SignatureExt.sellarSignatureConKeyDerSha1_1(
                            canonicalSignedInfo,
                            this.KEYPAIR
                    );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureSignatureValue = soapElementSolicitaDescargaSolicitudSignature.addChildElement(
                    "SignatureValue"
            );
            soapElementSolicitaDescargaSolicitudSignatureSignatureValue.addTextNode(
                    this.SELLOB64
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfo = soapElementSolicitaDescargaSolicitudSignature.addChildElement(
                    "KeyInfo"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509Data = soapElementSolicitaDescargaSolicitudSignatureKeyInfo.addChildElement(
                    "X509Data"
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerial = soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509Data.addChildElement(
                    "X509IssuerSerial"
            );

            CerDer cerDer = new CerDer(this.BYTECER);
            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerialX509IssuerName = soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerial.addChildElement(
                    "X509IssuerName"
            );
            soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerialX509IssuerName.addTextNode(
                    cerDer.getIssuer()
            );

            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerialX509SerialNumber = soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerial.addChildElement(
                    "X509SerialNumber"
            );
            soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509IssuerSerialX509SerialNumber.addTextNode(
                    cerDer.getSerialNumber()
            );

            String cerB64 = Base64.getEncoder().encodeToString(this.BYTECER);
            SOAPElement soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509Certificate = soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509Data.addChildElement(
                    "X509Certificate"
            );
            soapElementSolicitaDescargaSolicitudSignatureKeyInfoX509DataX509Certificate.addTextNode(
                    cerB64
            );
        } catch (SOAPException exc) {
            throw new RuntimeException(
                    "Error al crear el nodo Body - SolicitaDescarga - solicitud - Signature",
                    exc
            );
        }
    }

    private String getCanonicalTimestamp() {
        String canonicalTimestamp = "";
        if (this.RFCRECEPTOR != null) {
            canonicalTimestamp =
                    "<des:SolicitaDescarga xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">" +
                            "<des:solicitud RfcEmisor=\"" +
                            this.RFCEMISOR +
                            "\" RfcReceptor=\"" +
                            this.RFCRECEPTOR +
                            "\" RfcSolicitante=\"" +
                            this.RFCSOLICITANTE +
                            "\" FechaInicial=\"" +
                            this.INICIO +
                            "\" FechaFinal=\"" +
                            this.FIN +
                            "\" TipoSolicitud=\"CFDI\">" +
                            "</des:solicitud>" +
                            "</des:SolicitaDescarga>";
        } else {
            canonicalTimestamp =
                    "<des:SolicitaDescarga xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">" +
                            "<des:solicitud RfcEmisor=\"" +
                            this.RFCEMISOR +
                            "\" RfcSolicitante=\"" +
                            this.RFCSOLICITANTE +
                            "\" FechaInicial=\"" +
                            this.INICIO +
                            "\" FechaFinal=\"" +
                            this.FIN +
                            "\" TipoSolicitud=\"CFDI\">" +
                            "</des:solicitud>" +
                            "</des:SolicitaDescarga>";
        }
        return canonicalTimestamp;
    }

    private String getCanonicalSignedInfo(String digest) {
        String canonicalSignedInfo =
                "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod>" +
                        "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>" +
                        "<Reference URI=\"#_0\">" +
                        "<Transforms>" +
                        "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform>" +
                        "</Transforms>" +
                        "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>" +
                        "<DigestValue>" +
                        digest +
                        "</DigestValue>" +
                        "</Reference>" +
                        "</SignedInfo>";
        return canonicalSignedInfo;
    }
}

*/
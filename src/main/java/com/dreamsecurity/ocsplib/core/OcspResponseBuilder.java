package com.dreamsecurity.ocsplib.core;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.dreamsecurity.ocsputility.Constants;
import com.dreamsecurity.ocsputility.CryptoUtil;

public class OcspResponseBuilder {

	Logger logger = LogManager.getLogger(OcspResponseBuilder.class);

	private BasicOCSPResp basicOCSPResp = null;
	private OCSPResp ocspResp = null;	
	private JcaBasicOCSPRespBuilder basicRespBuilder = null;
	
	public OcspResponseBuilder(PublicKey responderPubKey) {
		try {
			this.basicRespBuilder = new JcaBasicOCSPRespBuilder(
					responderPubKey, 
					new JcaDigestCalculatorProviderBuilder().setProvider(Constants.bc_provider).build()
						.get(new DefaultDigestAlgorithmIdentifierFinder().find(Constants.HashAlgo.sha1.getValue())));
		} catch (OperatorCreationException | OCSPException e) {
			logger.error("Error in initializing basic response class: " + e.getMessage());
			e.printStackTrace();			
		}
	}
	
	public OcspResponseBuilder(byte[] ocspResp) {
		try {
			this.ocspResp = new OCSPResp(ocspResp);			
		} catch (IOException e) {
			logger.error("Invalid ocspResp data: " + e.getMessage());
			e.printStackTrace();
		}
		
		this.basicOCSPResp = new BasicOCSPResp( BasicOCSPResponse.getInstance(
				 this.ocspResp.toASN1Structure().getResponseBytes().getResponse()));		
	}
	
	public BasicOCSPResp getBasicOcspResp() {
		return this.basicOCSPResp;		
	}
	
	public int getOcspRespStatus() {
		if(this.ocspResp != null) {
			return this.ocspResp.getStatus();
		} else {
			logger.error("OcspResp is null, initialize the ocsp reponse first");
			return -1;
		}
	}
	
	public OCSPResp getOcspResp() {
		return this.ocspResp;
	}

	public int addSingleResponse(CertID certId, OcspStatus certStatus, Date thisUpdate,
			Date nextUpdate, Extensions singleExtension) {
		
		CertificateStatus status = certStatus.getOcspStatusValue(); 
				
		this.basicRespBuilder.addResponse(new CertificateID(certId), status, thisUpdate, nextUpdate, singleExtension);
		
		return 0;
	}
	
	public int addSingleResponse(CertID certId, OcspStatus certStatus, Date nextUpdate, 
			Extensions singleExtension) {
		
		CertificateStatus status = certStatus.getOcspStatusValue();
				
		
		this.basicRespBuilder.addResponse(new CertificateID(certId), status, nextUpdate, singleExtension);
		
		return 0;
	}
	
	public int addSingleResponse(CertID certId, OcspStatus certStatus, Date thisUpdate, Date nextUpdate) {
		
		CertificateStatus status = certStatus.getOcspStatusValue();
				
		this.basicRespBuilder.addResponse(new CertificateID(certId), status, thisUpdate, nextUpdate);
		
		return 0;
	}
	
	public int addSingleResponse(CertID certId, OcspStatus certStatus, Extensions singleExtension) {
		
		CertificateStatus status = certStatus.getOcspStatusValue();
		
		this.basicRespBuilder.addResponse(new CertificateID(certId), status, singleExtension);
		
		return 0;
	}
	
	public int addSingleResponse(CertID certId, OcspStatus certStatus) {
		
		CertificateStatus status = certStatus.getOcspStatusValue();
				
		this.basicRespBuilder.addResponse(new CertificateID(certId), status);
		
		return 0;
	}	
		
	public void setOcspRespExts(Extensions exts) {		
		this.basicRespBuilder.setResponseExtensions(exts);		
	}

	public OCSPResp build(PrivateKey signingPrivateKey, String signatureAlgo, 
			X509CertificateHolder[] chain, 
			Date producedAt, Extensions basicRespExts,
			int responseStatus) {
		
		ContentSigner signer = null;
		
		try {
			signer = new JcaContentSignerBuilder(signatureAlgo)
					.build(signingPrivateKey);
		} catch (OperatorCreationException e) {
			logger.error("Error in creating OCSP BasicResponse: " + e.getMessage() );									
			e.printStackTrace();		
			return null;			
		}		
		
		if(basicRespExts != null) {
			this.basicRespBuilder.setResponseExtensions(basicRespExts);
		}
		
		try {
			this.basicOCSPResp = this.basicRespBuilder.build(signer, chain, producedAt);
		} catch (OCSPException e) {
			logger.error("Error in creating OCSP BasicResponse: " + e.getMessage() );	
			e.printStackTrace();
			return null;
		}
		
		OCSPRespBuilder builder = new OCSPRespBuilder();
		
		try {
			this.ocspResp = builder.build(responseStatus, this.basicOCSPResp);
		} catch (OCSPException e) {
			logger.error("Failed to build OCSPResponse: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		
		return this.ocspResp;
	}
	
	public boolean verifySignerCertChain (List<X509Certificate> trustedAnchorCerts) {
		JcaX509CertificateConverter conv = new JcaX509CertificateConverter();		
		List<X509Certificate> interCerts = new ArrayList<>();
		
		X509CertificateHolder[] ha = this.basicOCSPResp.getCerts();
		X509Certificate signerCert = null;
		
		try {
			signerCert = conv.getCertificate(ha[0]);	
		
			for(int i = 1; i < ha.length; i++) {
				interCerts.add(conv.getCertificate(ha[i]));
			}
		} catch (CertificateException e) {
			logger.error("Error in converting X509CertificateHolder to X509Certificate: " + e.getMessage());
			e.printStackTrace();			
		}		
		
		return CryptoUtil.verifyCertificateBoolean(				
					signerCert, 
					trustedAnchorCerts,
					interCerts);
	}
	
	public boolean verifySignature() {			
		try {
			return this.basicOCSPResp.isSignatureValid(new JcaContentVerifierProviderBuilder()
					.setProvider(Constants.bc_provider)
					.build(this.basicOCSPResp.getCerts()[0]));
		} catch (OperatorCreationException | CertificateException | OCSPException e) {
			logger.debug("OCSP Request signature verification failed: " + e.getMessage());
			e.printStackTrace();
			return false;
		}
	}
}

package com.dreamsecurity.ocsplib.core;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.dreamsecurity.ocsputility.Constants;
import com.dreamsecurity.ocsputility.CryptoUtil;

/**
 * OCSP request builder class according to RFC 6960 and can produce 
 * signed and unsigned OCSP request messages.
 * 
 * An OCSP request contains the following data:
 * - protocol version
 * - service request
 * - target certificate identifier
 * - optional extensions, which MAY be processed by the OCSP responder
 * 
 * @author dream
 */
public class OcspRequestBuilder {

	Logger logger = LogManager.getLogger(OcspRequestBuilder.class);
	
	private OCSPReq ocspReq = null;
	private OCSPReqBuilder reqBuilder = null;
	
	public OcspRequestBuilder() {
		this.reqBuilder = new OCSPReqBuilder();
	}
	
	public OcspRequestBuilder(byte[] encReq) throws IOException {
		//try {
			this.ocspReq = new OCSPReq(encReq);
		/*} catch (IOException e) {
			logger.error("Invalid OCSP Request message: " + e.getMessage());
			e.printStackTrace();			
		}*/
	}
	
	public OCSPReq getOCSPRequest() {
		return this.ocspReq;
	}
	
	public boolean verifySignerCertChain(List<X509Certificate> trustedAnchorCerts) {
		JcaX509CertificateConverter conv = new JcaX509CertificateConverter();		
		List<X509Certificate> interCerts = new ArrayList<>();
		
		X509CertificateHolder[] ha = this.ocspReq.getCerts();
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
		if(!this.ocspReq.isSigned()) {
			logger.info("OCSP Request has no signature");
			return false;
		}
		
		// check signature	
		try {
			return this.ocspReq.isSignatureValid(new JcaContentVerifierProviderBuilder()
					.setProvider(Constants.bc_provider)
					.build(this.ocspReq.getCerts()[0]));
		} catch (OperatorCreationException | CertificateException | OCSPException e) {
			logger.debug("OCSP Request signature verification failed: " + e.getMessage());
			e.printStackTrace();
			return false;
		}		
	}
	
	/**
	 * Create SingleOCSPRequest from certificate and 
	 * SingleOCSPResquest extensions.
	 * 
	 * @param encCert Request certificate as byte array
	 * @param singleRequestExts  Extensions to be included in SingleOCSPRequest
	 * @return
	 */
	public int addRequestCert(byte[] issuerCert, BigInteger serialNumber, Extensions singleRequestExts) {
		return addCertId(issuerCert, serialNumber, singleRequestExts);
	}
		
	/**
	 * Add SingleOCSPRequest
	 * 
	 * @param issuerCert Issuer Certificate
	 * @param serialNumber Requested certificate serial number
	 * @return
	 */
	public int addRequestCert(byte[] issuerCert, BigInteger serialNumber) {
		return addCertId(issuerCert, serialNumber, null);		
	}
	
	private int addCertId(byte[] issuerCert, BigInteger serialNumber, Extensions singleRequestExts ) {			
		CertificateID certId = CryptoUtil.getOCSPCertId(issuerCert, serialNumber);
		
		if(certId == null) {						
			return 1;
		}
		
		if(singleRequestExts != null) {
			this.reqBuilder.addRequest(certId, singleRequestExts);
		} else {
			this.reqBuilder.addRequest(certId);
		}			
		return 0;		
	}
	
	/**
	 * Set OCSP requestor name
	 * @param requestorName OCSP requestor name
	 */
	public void setRequestorName(String requestorName) {
		this.reqBuilder.setRequestorName(
				new GeneralName(GeneralName.rfc822Name,requestorName));		
	}
	
	/**
	 * Set OCSP requestor name
	 * @param requestorName OCSP requestor name
	 */
	public void setRequestorName(GeneralName requestorName) {
		this.reqBuilder.setRequestorName(requestorName);		
	}
	
	/**
	 * Set OCSPRequest extensions
	 * @param requestExtensions OCSP request extensions
	 */
	public void setRequestExtension(Extensions requestExtensions) {
		this.reqBuilder.setRequestExtensions(requestExtensions);	
	}
	
	/**
	 * Build OCSPRequest message
	 * @return
	 */
	public OCSPReq build() {
		try {
			return this.reqBuilder.build();
		} catch (OCSPException e) {
			logger.error("Error in creating OCSP Request: " + e.getMessage() );									
			e.printStackTrace();		
			return null;
		}
	}
	
	/**
	 * Build signed OCSPReq message
	 * 
	 * @param privateKey Private key used to sign OCSP request
	 * @param signatureAlgo Signature algorithm
	 * @param certChain Certificates the server needs to verify 
	 * 		  the signed request (normally up to but not 
	 *        including the client’s root certificate).
	 * @return
	 */
	public OCSPReq build(PrivateKey privateKey, String signatureAlgo, X509CertificateHolder[] certChain) {		
		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder(signatureAlgo)
			.build(privateKey);
		} catch (OperatorCreationException e) {
			logger.error("Error in creating OCPS Request: " + e.getMessage() );									
			e.printStackTrace();		
			return null;			
		}
		
		try {			
			return this.reqBuilder.build(signer, certChain);
		} catch (IllegalArgumentException | OCSPException e) {
			logger.error("Error in creating OCPS Request: " + e.getMessage() );									
			e.printStackTrace();		
			return null;
		}
	}
}

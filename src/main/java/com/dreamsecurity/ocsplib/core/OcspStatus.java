package com.dreamsecurity.ocsplib.core;

import java.io.InvalidObjectException;
import java.security.InvalidParameterException;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;

public class OcspStatus implements CertificateStatus {

	Logger logger = LogManager.getLogger(OcspStatus.class);
		
	private CertificateStatus statusValue = null;
	
	public OcspStatus (CertificateStatus status) throws InvalidObjectException {
		if(status == CertificateStatus.GOOD || status instanceof UnknownStatus
				|| status instanceof RevokedStatus) {
			statusValue = status;
		} else {
			throw new InvalidObjectException("Not instance of CertificateStatus.class");
		} 
	}
	
	public OcspStatus (OCSP_STATUS status) {
				
		if(status == OCSP_STATUS.OCSP_GOOD ) {
			this.statusValue = CertificateStatus.GOOD;
		} else if ( status == OCSP_STATUS.OCSP_UNKNOWN) {
			this.statusValue = new UnknownStatus();
		} else if(status == OCSP_STATUS.OCSP_REVOKED) {
			logger.error("Set the revocation date and crl reason");
			throw new InvalidParameterException("Set the revocation date and crl reason");
		}
	}
	
	public OcspStatus (OCSP_STATUS status, Date revocationDate, int crlReason) {
		
		if(status == OCSP_STATUS.OCSP_GOOD ) {
			this.statusValue = CertificateStatus.GOOD;
		} else if ( status == OCSP_STATUS.OCSP_UNKNOWN) {
			this.statusValue = new UnknownStatus();
		} else if(status == OCSP_STATUS.OCSP_REVOKED) {
			this.statusValue = new RevokedStatus(revocationDate, crlReason);
		}
	}			

	public CertificateStatus getOcspStatusValue() {
		return this.statusValue;
	}	
	
	public static enum OCSP_STATUS {
		OCSP_GOOD,
	    OCSP_REVOKED,
	    OCSP_UNKNOWN;	
	}
}
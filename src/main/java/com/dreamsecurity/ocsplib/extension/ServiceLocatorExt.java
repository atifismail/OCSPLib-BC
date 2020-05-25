package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;

/**
 * An OCSP server may be operated in a mode whereby the server receives a
 * request and routes it to the OCSP server that is known to be authoritative
 * for the identified certificate. The serviceLocator request extension is
 * defined for this purpose. This extension is included as one of the
 * singleRequestExtensions in requests.
 * 
 * id-pkix-ocsp-service-locator OBJECT IDENTIFIER ::= {id-pkix-ocsp 7}
 * 
 * ServiceLocator ::= SEQUENCE { issuer Name, locator AuthorityInfoAccessSyntax
 * OPTIONAL }
 * 
 * Values for these fields are obtained from the corresponding fields in the
 * subject certificate.
 * 
 * @author dream
 *
 */
public class ServiceLocatorExt {
	Logger logger = LogManager.getLogger(ServiceLocatorExt.class);
	/**
	 * Note: This extension can be included as one of the
	 * singleRequestExtensions in requests.
	 * 
	 * @param issuer
	 *            Issuer of Issuer name (DN from subject certificate)
	 * @param locator
	 *            AuthorityInfoAccessSyntax OPTIONAL (AIA info from subject
	 *            certificate)
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(String issuer, AuthorityInformationAccess locator, boolean isCritical) {

		Extension ext = null;

		ASN1EncodableVector v = new ASN1EncodableVector(2);

		v.add(new X500Name(issuer));

		if (locator != null) {
			v.add(locator);
		}

		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_service_locator, isCritical,
					new DERSequence(v).getEncoded());	
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create Service Locator extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

}

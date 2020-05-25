package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * This extension indicates that the responder supports the extended definition
 * of the "revoked" status to also include non-issued certificates according to
 * Section 2.2. One of its main purposes is to allow audits to determine the
 * responder’s type of operation. Clients do not have to parse this extension in
 * order to determine the status of certificates in responses.
 * 
 * This extension MUST be included in the OCSP response when that response
 * contains a "revoked" status for a non-issued certificate. This extension MAY
 * be present in other responses to signal that the responder implements the
 * extended revoked definition. When included, this extension MUST be placed in
 * responseExtensions, and it MUST NOT appear in singleExtensions.
 * 
 * This extension is identified by the object identifier
 * id-pkix-ocsp-extended-revoke.
 * 
 * id-pkix-ocsp-extended-revoke OBJECT IDENTIFIER ::= {id-pkix-ocsp 9}
 * 
 * The value of the extension SHALL be NULL. This extension MUST NOT be marked
 * critical.
 * 
 * @author dream
 *
 */
public class ExtendedRevokedDefExt {
	Logger logger = LogManager.getLogger(ExtendedRevokedDefExt.class);
	
	/**
	 * Note: When included, this extension MUST be placed in responseExtensions,
	 * and it MUST NOT appear in singleExtensions. 
	 * The value of the extension SHALL be NULL. 
	 * This extension MUST NOT be marked critical.
	 * 
	 * @param isCritical
	 * @return
	 */
	public Extension build(boolean isCritical) {
		Extension ext = null;
		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke, isCritical,
					DERNull.INSTANCE.getEncoded());			
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create Extended Revoked extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
}

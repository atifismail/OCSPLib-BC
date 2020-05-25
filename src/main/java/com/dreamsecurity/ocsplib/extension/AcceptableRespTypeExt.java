package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * An OCSP client MAY wish to specify the kinds of response types it
 * understands. To do so, it SHOULD use an extension with the OID
 * id-pkix-ocsp-response and the value AcceptableResponses. This extension is
 * included as one of the requestExtensions in requests. The OIDs included in
 * AcceptableResponses are the OIDs of the various response types this client
 * can accept (e.g., id-pkix-ocsp-basic). id-pkix-ocsp-response OBJECT
 * IDENTIFIER ::= { id-pkix-ocsp 4 }
 * 
 * AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
 * 
 * As noted in Section 4.2.1, OCSP responders SHALL be capable of responding
 * with responses of the id-pkix-ocsp-basic response type. Correspondingly, OCSP
 * clients SHALL be capable of receiving and processing responses of the
 * id-pkix-ocsp-basic response type.
 * 
 * @author dream
 *
 */
public class AcceptableRespTypeExt {
	Logger logger = LogManager.getLogger(AcceptableRespTypeExt.class);

	/**
	 * An OCSP client MAY wish to specify the kinds of response types it
	 * understands. 
	 * Note: This extension can be included as one of the
	 * requestExtensions in OCSP request.
	 * 
	 * @param oidList
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(String[] oidList, boolean isCritical) {

		Extension ext = null;

		ASN1EncodableVector v = new ASN1EncodableVector();

		for (String oid : oidList) {
			v.add(new ASN1ObjectIdentifier(oid));
		}

		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_response, isCritical,
					new DERSequence(v).getEncoded());
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create Acceptable Response type extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

}

package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * It may be desirable for the OCSP responder to indicate the CRL on which a
 * revoked or onHold certificate is found. 
 * Note: These extensions can be used as singleResponseExtensions in response
 * 
 * id-pkix-ocsp-crl OBJECT IDENTIFIER ::= { id-pkix-ocsp 3 }
 *
 * CrlID ::= SEQUENCE { crlUrl [0] EXPLICIT IA5String OPTIONAL, crlNum [1]
 * EXPLICIT INTEGER OPTIONAL, crlTime [2] EXPLICIT GeneralizedTime OPTIONAL }
 *
 * For the choice crlUrl, the IA5String will specify the URL at which the CRL is
 * available. For crlNum, the INTEGER will specify the value of the CRL number
 * extension of the relevant CRL. For crlTime, the GeneralizedTime will indicate
 * the time at which the relevant CRL was issued.
 * 
 * @author dream
 *
 */
public class CRLReferenceExt {
	Logger logger = LogManager.getLogger(CRLReferenceExt.class);

	/**
	 * It may be desirable for the OCSP responder to indicate the CRL on
	 * which a revoked or onHold certificate is found.
	 * Note: These extensions can be used as singleResponseExtensions in response
	 * 
	 * @param crlUrl The URL at which the CRL is available
	 * @param crlNum CRL number
	 * @param crlTime The time at which the relevant CRL was created
	 * @param isCritical Specify if the extension is critical
	 * @return
	 */
	public Extension build(String crlUrl, Integer crlNum, Date crlTime, boolean isCritical) {

		Extension ext = null;

		ASN1EncodableVector v = new ASN1EncodableVector();
		if (crlUrl != null && !crlUrl.isEmpty()) {
			v.add(new DERTaggedObject(true, 0, new DERIA5String(crlUrl)));
		}
		if (crlNum != null && crlNum > 0) {
			v.add(new ASN1Integer(crlNum));
		}
		if (crlTime != null) {
			v.add(new ASN1GeneralizedTime(crlTime));
		}

		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_crl, isCritical, 
					new DERSequence(v).getEncoded());
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create OCSP CRL reference extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

}

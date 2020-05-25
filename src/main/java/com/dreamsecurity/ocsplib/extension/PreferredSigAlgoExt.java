package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * A client MAY declare a preferred set of algorithms in a request by including
 * a preferred signature algorithms extension in requestExtensions of the
 * OCSPRequest.
 *
 * id-pkix-ocsp-pref-sig-algs OBJECT IDENTIFIER ::= { id-pkix-ocsp 8 }
 *
 * PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
 *
 * PreferredSignatureAlgorithm ::= SEQUENCE { sigIdentifier AlgorithmIdentifier,
 * pubKeyAlgIdentifier SMIMECapability OPTIONAL }
 *
 * The syntax of AlgorithmIdentifier is defined in Section 4.1.1.2 of RFC 5280
 * [RFC5280]. The syntax of SMIMECapability is defined in RFC 5751 [RFC5751].
 *
 * sigIdentifier specifies the signature algorithm the client prefers, e.g.,
 * algorithm=ecdsa-with-sha256. Parameters are absent for most common signature
 * algorithms.
 * 
 * pubKeyAlgIdentifier specifies the subject public key algorithm identifier the
 * client prefers in the server’s certificate used to validate the OCSP
 * response, e.g., algorithm=id-ecPublicKey and parameters= secp256r1.
 * pubKeyAlgIdentifier is OPTIONAL and provides a means to specify parameters
 * necessary to distinguish among different usages of a particular algorithm,
 * e.g., it may be used by the client to specify what curve it supports for a
 * given elliptic curve algorithm.
 * 
 * @author dream
 */

public class PreferredSigAlgoExt {
	Logger logger = LogManager.getLogger(PreferredSigAlgoExt.class);
	
	public Extension build(List<PreferredSigAlgo> preferredSigAlgos, boolean isCritical) {
		Extension ext = null;

		ASN1EncodableVector v = new ASN1EncodableVector();

		preferredSigAlgos.forEach(sigAlgo -> {
			v.add(sigAlgo.build());
		});

		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs, isCritical,
					new DERSequence(v).getEncoded());			
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create Preferred signature algorithms extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
}

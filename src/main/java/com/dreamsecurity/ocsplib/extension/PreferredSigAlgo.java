package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Use for storing preferred signature algorithm 
 * value in PreferredSigAlgoExt
 * 
 * @author dream 
 */
public class PreferredSigAlgo {
	Logger logger = LogManager.getLogger(PreferredSigAlgo.class);
	
	private AlgorithmIdentifier sigIdentifier = null;
	private SMIMECapability pubKeyAlgIdentifier = null;
		
	public PreferredSigAlgo() {
		this.pubKeyAlgIdentifier = null;
		this.sigIdentifier = null;
	}

	public PreferredSigAlgo(String signId, String pubKeyId,
			ASN1Encodable parameters) {

		this.sigIdentifier = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier(signId));

		this.pubKeyAlgIdentifier = new SMIMECapability(
				new ASN1ObjectIdentifier(pubKeyId), parameters);

	}

	public static PreferredSigAlgo getInstance(Object obj) {
		if (obj instanceof PreferredSigAlgo) {
			return (PreferredSigAlgo) obj;
		}

		if (obj != null) {
			return new PreferredSigAlgo(ASN1Sequence.getInstance(obj));
		}

		return null;
	}

	private PreferredSigAlgo(ASN1Sequence seq) {
		if (seq.size() < 1) {
			throw new IllegalArgumentException("sequence may not be empty");
		}

		this.sigIdentifier = AlgorithmIdentifier
				.getInstance(seq.getObjectAt(0));

		if(seq.size() > 1) {		
			this.pubKeyAlgIdentifier = SMIMECapability
					.getInstance(seq.getObjectAt(1));
		}
	}

	public AlgorithmIdentifier getSigIdentifier() {
		return sigIdentifier;
	}
	public void setSigIdentifier(String sigIdentifier) {
		this.sigIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigIdentifier));
	}
	public SMIMECapability getPubKeyAlgIdentifier() {
		return pubKeyAlgIdentifier;
	}
	
	public void setPubKeyAlgIdentifier(String pubKeyAlgIdentifier) {
		try {
			this.pubKeyAlgIdentifier = new SMIMECapability(ASN1Sequence.getInstance(
					new ASN1InputStream(
							new ASN1ObjectIdentifier(pubKeyAlgIdentifier).getEncoded())));
		} catch (IOException e) {
			logger.error("Failed to create pubKeyAlgIdentifier: " + e.getMessage());
			e.printStackTrace();
			return;
		}	
	}
	
	public ASN1Sequence build() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		v.add(sigIdentifier);
		if(this.pubKeyAlgIdentifier != null) {
			v.add(this.pubKeyAlgIdentifier);
		}
		
		return new DERSequence(v);
	}
	
}
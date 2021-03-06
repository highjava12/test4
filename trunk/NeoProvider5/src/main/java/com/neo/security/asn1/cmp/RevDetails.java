package com.neo.security.asn1.cmp;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.crmf.CertTemplate;
import com.neo.security.asn1.x509.ReasonFlags;
import com.neo.security.asn1.x509.X509Extensions;

public class RevDetails
    extends ASN1Encodable
{
    private CertTemplate certDetails;
    private ReasonFlags revocationReason;
    private X509Extensions crlEntryDetails;

    private RevDetails(ASN1Sequence seq)
    {
        certDetails = CertTemplate.getInstance(seq.getObjectAt(0));
        if  (seq.size() > 1)
        {
            crlEntryDetails = X509Extensions.getInstance(seq.getObjectAt(1));
        }
    }

    public static RevDetails getInstance(Object o)
    {
        if (o instanceof RevDetails)
        {
            return (RevDetails)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new RevDetails((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public RevDetails(CertTemplate certDetails, ReasonFlags revocationReason, X509Extensions crlEntryDetails )
    {
    	this.certDetails = certDetails;
    	this.revocationReason = revocationReason;
    	this.crlEntryDetails = crlEntryDetails;
    }
    
    public CertTemplate getCertDetails()
    {
        return certDetails;
    }

    public X509Extensions getCrlEntryDetails()
    {
        return crlEntryDetails;
    }

    /**
     * <pre>
     * RevDetails ::= SEQUENCE {
     *                  certDetails         CertTemplate,
     *                   -- allows requester to specify as much as they can about
     *                   -- the cert. for which revocation is requested
     *                   -- (e.g., for cases in which serialNumber is not available)
     *                   crlEntryDetails     Extensions       OPTIONAL
     *                   -- requested crlEntryExtensions
     *             }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certDetails);
//        if (revocationReason != null)
//        {
//        	v.add(revocationReason);
//        }
        if (crlEntryDetails != null)
        {
            v.add(crlEntryDetails);
        }

        return new DERSequence(v);
    }
}

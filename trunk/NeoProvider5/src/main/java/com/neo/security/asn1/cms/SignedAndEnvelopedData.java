package com.neo.security.asn1.cms;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1Set;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.BERSequence;
import com.neo.security.asn1.BERSet;
import com.neo.security.asn1.BERTaggedObject;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DERTaggedObject;

/**
 * a signed data object.
 */
public class SignedAndEnvelopedData
    extends ASN1Encodable
{
    private DERInteger  	version;
    private ASN1Set         recipientInfos;
    private ASN1Set    		digestAlgorithms;
    private EncryptedContentInfo 	encryptedContentInfo;
    private ASN1Set     	certificates;
    private ASN1Set     	crls;
    private ASN1Set     	signerInfos;
    private boolean 		certsBer;
    private boolean        	crlsBer;

    
    
    public static SignedAndEnvelopedData getInstance(
        Object  o)
    {
        if (o instanceof SignedAndEnvelopedData)
        {
            return (SignedAndEnvelopedData)o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new SignedAndEnvelopedData((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    
    public SignedAndEnvelopedData(
    	ASN1Set     recipientInfos,
        ASN1Set     digestAlgorithms,
        EncryptedContentInfo encryptedContentInfo,
        ASN1Set     certificates,
        ASN1Set     crls,
        ASN1Set     signerInfos)
    {
        this.version = calculateVersion(encryptedContentInfo.getContentType(), certificates, crls, signerInfos);
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
        this.crlsBer = crls instanceof BERSet;
        this.certsBer = certificates instanceof BERSet;
    }


    // RFC3852, section 5.1:
    // IF ((certificates is present) AND
    //    (any certificates with a type of other are present)) OR
    //    ((crls is present) AND
    //    (any crls with a type of other are present))
    // THEN version MUST be 5
    // ELSE
    //    IF (certificates is present) AND
    //       (any version 2 attribute certificates are present)
    //    THEN version MUST be 4
    //    ELSE
    //       IF ((certificates is present) AND
    //          (any version 1 attribute certificates are present)) OR
    //          (any SignerInfo structures are version 3) OR
    //          (encapContentInfo eContentType is other than id-data)
    //       THEN version MUST be 3
    //       ELSE version MUST be 1
    //
    private DERInteger calculateVersion(
        DERObjectIdentifier contentOid,
        ASN1Set certs,
        ASN1Set crls,
        ASN1Set signerInfs)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (certs != null)
        {
            for (Enumeration en = certs.getObjects(); en.hasMoreElements();)
            {
                Object obj = en.nextElement();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return new DERInteger(5);
        }

        if (crls != null)         // no need to check if otherCert is true
        {
            for (Enumeration en = crls.getObjects(); en.hasMoreElements();)
            {
                Object obj = en.nextElement();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return new DERInteger(5);
        }

        if (attrCertV2Found)
        {
            return new DERInteger(4);
        }

        if (attrCertV1Found)
        {
            return new DERInteger(3);
        }

        if (contentOid.equals(CMSObjectIdentifiers.data))
        {
            if (checkForVersion3(signerInfs))
            {
                return new DERInteger(3);
            }
            else
            {
                return new DERInteger(1);
            }
        }
        else
        {
            return new DERInteger(3);
        }
    }

    private boolean checkForVersion3(ASN1Set signerInfs)
    {
        for (Enumeration e = signerInfs.getObjects(); e.hasMoreElements();)
        {
            SignerInfo s = SignerInfo.getInstance(e.nextElement());

            if (s.getVersion().getValue().intValue() == 3)
            {
                return true;
            }
        }

        return false;
    }


    
    public SignedAndEnvelopedData(
        ASN1Sequence seq)
    {
        Enumeration     e = seq.getObjects();

        version = (DERInteger)e.nextElement();
        recipientInfos = (ASN1Set)e.nextElement();
        digestAlgorithms = ((ASN1Set)e.nextElement());
        encryptedContentInfo = EncryptedContentInfo.getInstance(e.nextElement());

        while (e.hasMoreElements())
        {
            DERObject o = (DERObject)e.nextElement();

            //
            // an interesting feature of SignedData is that there appear
            // to be varying implementations...
            // for the moment we ignore anything which doesn't fit.
            //
            if (o instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject tagged = (ASN1TaggedObject)o;

                switch (tagged.getTagNo())
                {
                case 0:
                    certsBer = tagged instanceof BERTaggedObject;
                    certificates = ASN1Set.getInstance(tagged, false);
                    break;
                case 1:
                    crlsBer = tagged instanceof BERTaggedObject;
                    crls = ASN1Set.getInstance(tagged, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
                }
            }
            else
            {
                signerInfos = (ASN1Set)o;
            }
        }
    }

    public DERInteger getVersion()
    {
        return version;
    }

    public ASN1Set getDigestAlgorithms()
    {
        return digestAlgorithms;
    }

    public EncryptedContentInfo getEncapContentInfo()
    {
        return encryptedContentInfo;
    }

    public ASN1Set getCertificates()
    {
        return certificates;
    }

    public ASN1Set getCRLs()
    {
        return crls;
    }

    public ASN1Set getSignerInfos()
    {
        return signerInfos;
    }

    
    public ASN1Set getRecipientInfos() {
		return recipientInfos;
	}

	public EncryptedContentInfo getEncryptedContentInfo() {
		return encryptedContentInfo;
	}


	/**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * SignedData ::= SEQUENCE {
     *     version CMSVersion,
     *     digestAlgorithms DigestAlgorithmIdentifiers,
     *     encapContentInfo EncapsulatedContentInfo,
     *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     *     signerInfos SignerInfos
     *   }
     * </pre>
     */
	
    /*
     *     private DERInteger  	version;
    private ASN1Set         recipientInfos;
    private ASN1Set    		digestAlgorithms;
    private EncryptedContentInfo 	encryptedContentInfo;
    private ASN1Set     	certificates;
    private ASN1Set     	crls;
    private ASN1Set     	signerInfos;
     */
	
    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(version);
        v.add(recipientInfos);
        v.add(digestAlgorithms);
        v.add(encryptedContentInfo);

        if (certificates != null)
        {
            if (certsBer)
            {
                v.add(new BERTaggedObject(false, 0, certificates));
            }
            else
            {
                v.add(new DERTaggedObject(false, 0, certificates));
            }
        }

        if (crls != null)
        {
            if (crlsBer)
            {
                v.add(new BERTaggedObject(false, 1, crls));
            }
            else
            {
                v.add(new DERTaggedObject(false, 1, crls));
            }
        }

        v.add(signerInfos);

        return new BERSequence(v);
    }
}
package com.neo.security.asn1.misc;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.DERSequence;

public class CAST5CBCParameters
    extends ASN1Encodable
{
    DERInteger      keyLength;
    ASN1OctetString iv;

    public static CAST5CBCParameters getInstance(
        Object  o)
    {
        if (o instanceof CAST5CBCParameters)
        {
            return (CAST5CBCParameters)o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new CAST5CBCParameters((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("unknown object in CAST5CBCParameter factory");
    }

    public CAST5CBCParameters(
        byte[]  iv,
        int     keyLength)
    {
        this.iv = new DEROctetString(iv);
        this.keyLength = new DERInteger(keyLength);
    }

    public CAST5CBCParameters(
        ASN1Sequence  seq)
    {
        iv = (ASN1OctetString)seq.getObjectAt(0);
        keyLength = (DERInteger)seq.getObjectAt(1);
    }

    public byte[] getIV()
    {
        return iv.getOctets();
    }

    public int getKeyLength()
    {
        return keyLength.getValue().intValue();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * cast5CBCParameters ::= SEQUENCE {
     *                           iv         OCTET STRING DEFAULT 0,
     *                                  -- Initialization vector
     *                           keyLength  INTEGER
     *                                  -- Key length, in bits
     *                      }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(iv);
        v.add(keyLength);

        return new DERSequence(v);
    }
}

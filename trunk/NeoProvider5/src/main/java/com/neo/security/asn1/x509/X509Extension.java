package com.neo.security.asn1.x509;

import java.io.IOException;

import com.neo.security.asn1.ASN1Object;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.DERBoolean;

/**
 * an object for the elements in the X.509 V3 extension block.
 */
public class X509Extension
{
    boolean             critical;
    ASN1OctetString      value;

    public X509Extension(
        DERBoolean              critical,
        ASN1OctetString         value)
    {
        this.critical = critical.isTrue();
        this.value = value;
    }

    public X509Extension(
        boolean                 critical,
        ASN1OctetString         value)
    {
        this.critical = critical;
        this.value = value;
    }

    public boolean isCritical()
    {
        return critical;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public int hashCode()
    {
        if (isCritical())
        {
            return getValue().hashCode();
        }

        
        return ~getValue().hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof X509Extension))
        {
            return false;
        }

        X509Extension   other = (X509Extension)o;

        return other.getValue().equals(getValue())
            && (other.isCritical() == isCritical());
    }

    /**
     * Convert the value of the passed in extension to an object
     * @param ext the extension to parse
     * @return the object the value string contains
     * @exception IllegalArgumentException if conversion is not possible
     */
    public static ASN1Object convertValueToObject(
        X509Extension ext)
        throws IllegalArgumentException
    {
        try
        {
            return ASN1Object.fromByteArray(ext.getValue().getOctets());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't convert extension: " +  e);
        }
    }
}

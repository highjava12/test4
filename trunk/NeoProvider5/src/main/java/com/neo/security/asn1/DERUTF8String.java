package com.neo.security.asn1;



import java.io.IOException;

import com.neo.security.asn1.util.Strings;



/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1Object
    implements DERString
{
	byte[] string;

    /**
     * return an UTF8 string from the passed in object.
     * 
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
     */
    public static DERUTF8String getInstance(Object obj)
    {
        if (obj == null || obj instanceof DERUTF8String)
        {
            return (DERUTF8String)obj;
        }

        if (obj instanceof ASN1OctetString)
        {
            return new DERUTF8String(((ASN1OctetString)obj).getOctets());
        }

        if (obj instanceof ASN1TaggedObject)
        {
            return getInstance(((ASN1TaggedObject)obj).getObject());
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * return an UTF8 String from a tagged object.
     * 
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception IllegalArgumentException
     *                if the tagged object cannot be converted.
     */
    public static DERUTF8String getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(obj.getObject());
    }

    /**
     * basic constructor - byte encoded string.
     */
    DERUTF8String(byte[] string)
    {
//        this.string = Strings.fromUTF8ByteArray(string);
    	this.string = string;
    	/*
    	octet = string;
        try {
			this.string = new String(string,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			this.string = new String(string);
		}
        */
    	
//		System.out.println("decode2: " + this.string);
//    	System.out.println("decode: " + StringUtils.bin2printstr(string));
    	
//		try {
//			this.string = new String(string,"EUC-KR");
//		} catch (UnsupportedEncodingException e) {
//
//			 this.string = Strings.fromUTF8ByteArray(string);
//		}

    }

    /**
     * basic constructor
     */
    public DERUTF8String(String string)
    {
    	this.string = Strings.toUTF8ByteArray(string);
    }

    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
    }
    
    public String toString()
    {
        return getString();
    }

    public byte[] getOctet()
    {
    	return this.string;
    }
    
	public int hashCode()
    {
        return getString().hashCode();
    }

    
	boolean asn1Equals(DERObject o)
    {
        if (!(o instanceof DERUTF8String))
        {
            return false;
        }

        DERUTF8String s = (DERUTF8String)o;

        return getString().equals(s.getString());
    }


	  void encode(DEROutputStream out)
		        throws IOException
	 {
	    out.writeEncoded(UTF8_STRING, string);
	 }
	
//	void encode(DEROutputStream out)
//        throws IOException
//    {
//		try {
////			System.out.println("encode: " + new String(string.getBytes("UTF8"),"UTF8"));
////			System.out.println("encode: " + StringUtils.bin2printstr(string.getBytes("8859_1")));
////			System.out.println("encode: " + StringUtils.bin2printstr(string.getBytes("UTF8")));
////			System.out.println("encode: " + StringUtils.bin2printstr(string.getBytes("EUC-KR")));
//			//out.writeEncoded(UTF8_STRING, string.getBytes("EUC-KR"));
//			
//			if (octet != null)
//			{
//				out.writeEncoded(UTF8_STRING, octet);
//			} else {
//				out.writeEncoded(UTF8_STRING, Strings.toUTF8ByteArray(string));
//			}
//		}catch(Exception e)
//		{
////			System.out.println(string);
//			out.writeEncoded(UTF8_STRING, string.getBytes("UTF8"));
//		}
//		//out.writeEncoded(UTF8_STRING, string.getBytes("UTF-8"));
//    }
}

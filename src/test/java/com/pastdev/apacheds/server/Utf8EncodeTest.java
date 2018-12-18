package com.pastdev.apacheds.server;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;


import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;


import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Utf8EncodeTest {
    private static Logger logger = LoggerFactory.getLogger( Utf8EncodeTest.class );
    private static final Charset UTF8 = Charset.forName( "UTF-8" );
    private static final String PASSWORD = "passwordText";

    @Test
    public void utf8EncodeTest() {
        CharBuffer charBuffer = CharBuffer.wrap( PASSWORD.toCharArray() );
        assertEquals( 12, charBuffer.length() );
        ByteBuffer byteBuffer = UTF8.encode( charBuffer );
        assertEquals( 12, byteBuffer.remaining() );
        byte[] encoded = new byte[byteBuffer.remaining()];
        byteBuffer.get( encoded );
        assertEquals( 12, encoded.length );
        logger.debug( "encoded='{}', {}", encoded, encoded.length );
        assertArrayEquals( PASSWORD.getBytes( UTF8 ), encoded );
    }

}

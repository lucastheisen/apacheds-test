package com.pastdev.apacheds.server;


import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;


import org.apache.directory.api.ldap.schema.extractor.UniqueResourceException;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An aspect workaround for <a
 * href="https://issues.apache.org/jira/browse/DIRSERVER-1606"
 * >DIRSERVER-1606</a>
 * 
 * @author LTHEISEN 
 */
@Aspect
public class GetUniqueResourceReplacer {
    private static final Logger log = LoggerFactory.getLogger( GetUniqueResourceReplacer.class );

    @Pointcut( "execution(* org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor.getUniqueResource(String,String)) &&" +
            "args(resourceName,resourceDescription)" )
    private void getUniqueResourceReplacer( String resourceName, String resourceDescription ) {
    }

    @Around( "com.pastdev.apacheds.server.GetUniqueResourceReplacer.getUniqueResourceReplacer(resourceName,resourceDescription)" )
    public URL getFirstMatchingResource( String resourceName, String resourceDescription ) throws IOException {
        Enumeration<URL> resources = DefaultSchemaLdifExtractor.class.getClassLoader().getResources( resourceName );
        if ( !resources.hasMoreElements() ) {
            throw new UniqueResourceException( resourceName, resourceDescription );
        }
        URL result = resources.nextElement();
        if ( resources.hasMoreElements() ) {
            log.debug( "found more than one copy of " + resourceName + " using first one" );
        }
        return result;
    }
}

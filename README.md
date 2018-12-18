# Using AOP to allow embedded apacheds for unit tests

The pertinent parts are

* [configure surefire to use aop](https://github.com/lucastheisen/apacheds-test/blob/master/pom.xml#L159-L166):
```
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <configuration>
          <argLine>-Xmx1024m
            -javaagent:"${settings.localRepository}/org/aspectj/aspectjweaver/${aspectj.version}/aspectjweaver-${aspectj.version}.jar"</argLine>
        </configuration>
      </plugin>
```

* [configure your aop](https://github.com/lucastheisen/apacheds-test/blob/master/src/main/resources/META-INF/aop.xml)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aspectj>

<aspectj>
  <aspects>
    <aspect name="com.pastdev.apacheds.server.GetUniqueResourceReplacer" />
  </aspects>
</aspectj>
```

* [replace the `getUniqueResource` method](https://github.com/lucastheisen/apacheds-test/blob/master/src/main/java/com/pastdev/apacheds/server/GetUniqueResourceReplacer.java)
```
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
```

I may have missed something else, but this project is a working example that demonstrates how i test my password policy.

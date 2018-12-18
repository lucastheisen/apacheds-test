package com.pastdev.apacheds.server.core.factory;


import java.io.File;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import org.apache.directory.server.config.ConfigPartitionInitializer;
import org.apache.directory.server.config.ConfigPartitionReader;
import org.apache.directory.server.config.beans.ConfigBean;
import org.apache.directory.server.config.beans.DirectoryServiceBean;
import org.apache.directory.server.config.builder.ServiceBuilder;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import com.pastdev.apacheds.server.core.factory.ResourceExtractor.FileNamer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ConfigDirectoryServiceFactory extends DefaultDirectoryServiceFactory {
    /** A logger for this class */
    private static final Logger logger = LoggerFactory.getLogger( ConfigDirectoryServiceFactory.class );
    private static final Pattern CONFIG_INDEX_ENTRY = Pattern.compile( "^[/\\\\]conf[/\\\\](.*)$" );

    public ConfigDirectoryServiceFactory() {}

    @Override
    public void init( String name ) throws Exception {
        super.init( name );
        DirectoryService directoryService = getDirectoryService();

        InstanceLayout instanceLayout = directoryService.getInstanceLayout();
        final File configDirectory = instanceLayout.getConfDirectory();
        ResourceExtractor.extractResources()
                .fromIndex( "/META-INF/apacheds-config.index" )
                .to( new FileNamer() {
                    @Override
                    public File name( String name ) {
                        Matcher matcher = CONFIG_INDEX_ENTRY.matcher( name );
                        if ( matcher.matches() ) {
                            return new File( configDirectory, matcher.group( 1 ) );
                        }
                        return null;
                    }
                } );

        // get all interceptors from config.ldif
        LdifPartition configPartition =
                new ConfigPartitionInitializer(
                        instanceLayout,
                        directoryService.getDnFactory(),
                        directoryService.getCacheService(),
                        directoryService.getSchemaManager() )
                        .initConfigPartition();
        ConfigBean configBean = new ConfigPartitionReader( configPartition )
                .readConfig();
        DirectoryServiceBean directoryServiceBean = configBean.getDirectoryServiceBean();
        List<Interceptor> interceptors = ServiceBuilder
                .createInterceptors( directoryServiceBean.getInterceptors() );
        for ( Interceptor interceptor : interceptors ) {
            interceptor.init( directoryService );
        }

        for ( Interceptor interceptor : directoryService.getInterceptors() ) {
            // de-initialize default interceptors
            interceptor.destroy();
        }

        // add in interceptors from config
        logger.debug( "interceptors: {}", interceptors );
        directoryService.setInterceptors( interceptors );
    }
}

package com.pastdev.apacheds.server.core.factory;


import static org.junit.Assert.assertFalse;


import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import org.junit.Test;
import com.pastdev.apacheds.server.core.factory.ResourceExtractor.FileNamer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ResourceExtractorTest {
    private static final Logger logger = LoggerFactory.getLogger( ResourceExtractorTest.class );
    private static final Pattern CONFIG_INDEX_ENTRY = Pattern.compile( "^[/\\\\]conf[/\\\\](.*)$" );

    @Test
    public void testResolve() throws IOException {
        Path folder = Files.createTempDirectory( "resourceextractor" );
        try {
            logger.debug( "abc: [{}]", folder.resolve( "abc" ) );
            logger.debug( "abc/def: [{}]", folder.resolve( "abc/def" ) );
            logger.debug( "/abc/def: [{}]", folder.resolve( "/abc/def" ) );
            logger.debug( "abc\\def: [{}]", folder.resolve( "abc\\def" ) );
            logger.debug( "ou=config/ads-directoryserviceid=default/ou=servers/ads-serverid=ldapserver/ou=transports/ads-transportid=ldaps.ldif: [{}]", folder.resolve(
                    "ou=config/ads-directoryserviceid=default/ou=servers/ads-serverid=ldapserver/ou=transports/ads-transportid=ldaps.ldif" ) );
            logger.debug( ": [{}]", folder );
        }
        finally {
            // best effort delete all files/folders
            Files.walkFileTree( folder, EnumSet.noneOf( FileVisitOption.class ), Integer.MAX_VALUE,
                    new FileVisitor<Path>() {
                        @Override
                        public FileVisitResult preVisitDirectory( Path dir, BasicFileAttributes attrs ) throws IOException {
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile( Path file, BasicFileAttributes attrs ) throws IOException {
                            Files.delete( file );
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed( Path file, IOException exc ) throws IOException {
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult postVisitDirectory( Path dir, IOException exc ) throws IOException {
                            Files.delete( dir );
                            return FileVisitResult.CONTINUE;
                        }
                    } );
        }
    }

    @Test
    public void testExtract() throws IOException {
        final Path folder = Files.createTempDirectory( "resourceextractor" );
        try {
            long start = System.nanoTime();
            ResourceExtractor.extractResources()
                    .fromIndex( "/META-INF/apacheds-config.index" )
                    .to( new FileNamer() {
                        @Override
                        public File name( String name ) {
                            Matcher matcher = CONFIG_INDEX_ENTRY.matcher( name );
                            if ( matcher.matches() ) {
                                logger.debug( "{}\n{}\n{}", folder, matcher.group( 1 ),
                                        folder.resolve( matcher.group( 1 ) ) );
                                return folder.resolve( matcher.group( 1 ) ).toFile();
                            }
                            return null;
                        }
                    } );
            logger.info( "Extraction took [{}] seconds", (System.nanoTime() - start) / 1000000000.0 );
        }
        finally {
            // best effort delete all files/folders
            Files.walkFileTree( folder, EnumSet.noneOf( FileVisitOption.class ), Integer.MAX_VALUE,
                    new FileVisitor<Path>() {
                        @Override
                        public FileVisitResult preVisitDirectory( Path dir, BasicFileAttributes attrs ) throws IOException {
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile( Path file, BasicFileAttributes attrs ) throws IOException {
                            Files.delete( file );
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed( Path file, IOException exc ) throws IOException {
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult postVisitDirectory( Path dir, IOException exc ) throws IOException {
                            Files.delete( dir );
                            return FileVisitResult.CONTINUE;
                        }
                    } );
        }
        assertFalse( Files.exists( folder ) );
    }
}

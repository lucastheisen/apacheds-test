package com.pastdev.apacheds.server.core.factory;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ResourceExtractor {
    private static final Logger logger = LoggerFactory.getLogger( ResourceExtractor.class );

    private Source source;

    private ResourceExtractor() {}

    private void checkSource( boolean exists ) {
        if ( exists && source == null ) {
            throw new IllegalStateException( "Source is already set" );
        }
        else if ( !exists && source != null ) {
            throw new IllegalStateException( "Source is not set" );
        }
    }

    public static void copy( InputStream from, OutputStream to ) throws IOException {
        ReadableByteChannel in = Channels.newChannel( from );
        WritableByteChannel out = Channels.newChannel( to );

        final ByteBuffer buffer = ByteBuffer.allocateDirect( 16 * 1024 );
        while ( in.read( buffer ) != -1 ) {
            buffer.flip();
            out.write( buffer );
            buffer.compact();
        }
        buffer.flip();
        while ( buffer.hasRemaining() ) {
            out.write( buffer );
        }
    }

    private void extract( Extractor extractor ) throws IOException {
        for ( String resource : source.resourceNames() ) {
            logger.trace( "extracting [{}] using [{}]", resource, extractor );
            try (InputStream contents = getClass().getResourceAsStream( resource )) {
                extractor.extract( resource, contents );
            }
        }
    }

    public static ResourceExtractor extractResources() {
        return new ResourceExtractor();
    }

    public ResourceExtractor from( Source source ) {
        checkSource( false );
        this.source = source;
        return this;
    }

    public ResourceExtractor fromResources( List<String> resources ) {
        checkSource( false );
        this.source = new ListSource( resources );
        return this;
    }

    public ResourceExtractor fromResources( String... resources ) {
        checkSource( false );
        this.source = new ListSource( resources );
        return this;
    }

    public ResourceExtractor fromIndex( String indexName ) {
        checkSource( false );
        this.source = new IndexSource( indexName );
        return this;
    }
    
    public void to( File folder ) throws IOException {
        extract( new FileExtractor( folder ) );
    }
    
    public void to( FileNamer fileNamer ) throws IOException {
        extract( new FileExtractor( fileNamer ) );
    }

    public void using( Extractor extractor ) throws IOException {
        extract( extractor );
    }

    public static interface Extractor {
        public void extract( String name, InputStream contents ) throws IOException;
    }

    public static interface FileNamer {
        public File name( String name );
    }

    public static final class FileExtractor implements Extractor {
        private File folder;
        private FileNamer fileNamer;

        public FileExtractor( FileNamer fileNamer ) {
            this.fileNamer = fileNamer;
        }

        public FileExtractor( File folder ) {
            this.folder = folder;
        }

        @Override
        public void extract( String name, InputStream contents ) throws IOException {
            File file = null;
            if ( fileNamer == null ) {
                file = new File( folder, name );
            }
            else {
                file = fileNamer.name( name );
            }
            if ( file == null ) {
                throw new IllegalStateException( "Unable to determine file name for [" + name + "]" );
            }

            File parent = file.getParentFile();
            if ( !parent.exists() ) {
                parent.mkdirs();
            }

            try (FileOutputStream fileOutputStream = new FileOutputStream( file )) {
                copy( contents, fileOutputStream );
            }
        }
        
        @Override
        public String toString() {
            return "{FolderExtractor:{" + folder + "}}";
        }
    }

    public static final class IndexSource implements Source {
        private String indexName;

        public IndexSource( String indexName ) {
            this.indexName = indexName;
        }

        @Override
        public Iterable<String> resourceNames() {
            List<String> resources = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader( new InputStreamReader( getClass().getResourceAsStream( indexName ) ) )) {
                String resource = null;
                while ( (resource = reader.readLine()) != null ) {
                    resources.add( "/" + resource );
                }
            }
            catch ( IOException e ) {
                throw new IllegalArgumentException( "Unable to read from index resource " + indexName );
            }
            return resources;
        }
    }

    public static final class ListSource implements Source {
        private List<String> resourceNames;

        public ListSource( String... resourceNames ) {
            this.resourceNames = Arrays.asList( resourceNames );
        }

        public ListSource( List<String> resourceNames ) {
            this.resourceNames = resourceNames;
        }

        @Override
        public Iterable<String> resourceNames() {
            return resourceNames;
        }
    }

    public static interface Source {
        public Iterable<String> resourceNames();
    }
}

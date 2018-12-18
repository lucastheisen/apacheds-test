package com.pastdev.apacheds.server;


import static org.apache.directory.server.core.integ.IntegrationUtils.getAdminNetworkConnection;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


import java.io.IOException;
import java.nio.charset.Charset;


import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyErrorEnum;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyImpl;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyDecorator;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.InterceptorEnum;
import org.apache.directory.server.core.api.LdapCoreSessionConnection;
import org.apache.directory.server.core.api.authn.ppolicy.CheckQualityEnum;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.apache.directory.server.ldap.handlers.extended.PwdModifyHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@CreateLdapServer(
        transports = {
                @CreateTransport( protocol = "LDAP" )
        },
        extendedOpHandlers = {
                PwdModifyHandler.class
        },
        allowAnonymousAccess = true )
@CreateDS( name = "classDS",
        enableChangeLog = true,
        partitions = {
                @CreatePartition(
                        name = "example",
                        suffix = "dc=example,dc=com",
                        contextEntry = @ContextEntry(
                                entryLdif =
                                "dn: dc=example,dc=com\n" +
                                        "objectClass: domain\n" +
                                        "objectClass: top\n" +
                                        "dc: asias\n\n"
                        ),
                        indexes = {
                                @CreateIndex( attribute = "objectClass" ),
                                @CreateIndex( attribute = "dc" ),
                                @CreateIndex( attribute = "ou" )
                        }
                )
        } )
@ApplyLdifFiles( {
        "conf/schema/test_pastdev_data.ldif",
        "conf/schema/test_data.ldif"
} )
public class PastdevPasswordPolicyTest {
    private static Logger logger = LoggerFactory.getLogger( PastdevPasswordPolicyTest.class );
    private static final Charset UTF_8 = Charset.forName( "UTF-8" );
    private static PasswordPolicyDecorator passwordPolicyRequestControl =
            new PasswordPolicyDecorator( LdapApiServiceFactory.getSingleton(), new PasswordPolicyImpl() );
    private static final ResponseEvaluator successNoWarningResponseEvaluator = new ResponseEvaluator() {
        @Override
        public void evaluate( LdapException exception, ResultResponse response, PasswordPolicy passwordPolicy ) {
            if ( logger.isTraceEnabled() ) {
                logger.trace( "Response: {}", response );
                logger.trace( "Policy: {}", (passwordPolicy == null ? "null" : passwordPolicy.getResponse()) );
                logger.trace( "Exception: {}", exception );
            }
            assertNull( exception );
            assertEquals( ResultCodeEnum.SUCCESS, response.getLdapResult().getResultCode() );
            assertTrue( passwordPolicy == null || passwordPolicy.getResponse() == null );
        }
    };

    @ClassRule
    public static CreateLdapServerRule classCreateLdapServerRule =
            new CreateLdapServerRule();

    @Rule
    public TestRule passwordPolicyAnnotationProcessingTestRule = new PasswordPolicyAnnotationProcessingTestRule(
            (AuthenticationInterceptor) classCreateLdapServerRule.getDirectoryService()
                    .getInterceptor( InterceptorEnum.AUTHENTICATION_INTERCEPTOR.getName() ) );

    private String testUserUid = "pwd_test_user";
    private String testUserPassword = "set4now";
    private Dn testUserDn;

    /**
     * For some reason revert is not removing stuff so we have to create and
     * destroy the test user for each case.
     * 
     * @throws Exception
     */
    @Before
    public void addTestUser() throws Exception {
        logger.trace( "adding test user {}", testUserUid );
        testUserDn = addUser(
                getAdminNetworkConnection( classCreateLdapServerRule.getLdapServer() ),
                testUserUid, testUserPassword );
    }

    private Dn addUser( LdapConnection connection, String uid, String password ) throws Exception {
        Entry userEntry = new DefaultEntry(
                "uid=" + uid + ",ou=people,dc=example,dc=com",
                "ObjectClass: top",
                "ObjectClass: person",
                "ObjectClass: organizationalPerson",
                "ObjectClass: inetOrgPerson",
                "uid", uid,
                "cn", uid + "_cn",
                "sn", uid + "_sn",
                "givenName", uid + "_givenName",
                "mail", uid + "@example.com",
                "userPassword", password );

        AddRequest addRequest = new AddRequestImpl();
        addRequest.setEntry( userEntry );
        addRequest.addControl( passwordPolicyRequestControl );

        AddResponse addResp = connection.add( addRequest );
        assertEquals( ResultCodeEnum.SUCCESS, addResp.getLdapResult().getResultCode() );
        PasswordPolicy respCtrl = getPasswordPolicyResponseControl( addResp );
        assertNull( respCtrl );

        return userEntry.getDn();
    }

    private BindResponse authenticate( LdapConnection connection, Dn dn, String password ) throws LdapException {
        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setDn( dn );
        bindRequest.setCredentials( password );
        bindRequest.addControl( passwordPolicyRequestControl );
        return connection.bind( bindRequest );
    }

    public void authenticate( final Dn userDn, final String password,
            final ResponseEvaluator evaluator ) {
        runWithConnection( new ConnectedTestCase() {
            @Override
            public void run( LdapConnection connection ) {
                LdapException exception = null;
                ResultResponse response = null;
                PasswordPolicy passwordPolicy = null;
                try {
                    response = authenticate( connection, userDn, password );
                    passwordPolicy = getPasswordPolicyResponseControl( response );
                }
                catch ( LdapException e ) {
                    exception = e;
                }
                evaluator.evaluate( exception, response, passwordPolicy );
            }
        } );
    }

    private BindResponse authenticateAdmin( LdapConnection connection ) throws LdapException {
        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setDn( new Dn( ServerDNConstants.ADMIN_SYSTEM_DN ) );
        bindRequest.setCredentials( "secret" );
        bindRequest.addControl( passwordPolicyRequestControl );
        return connection.bind( bindRequest );
    }

    private ModifyResponse changePassword( LdapConnection connection, Dn userDn, String password ) throws LdapException {
        ModifyRequest modifyRequest = new ModifyRequestImpl();
        modifyRequest.setName( userDn );
        modifyRequest.replace( "userPassword", password );
        modifyRequest.addControl( passwordPolicyRequestControl );
        return connection.modify( modifyRequest );
    }

    private void changePassword( final Dn userDn, final String oldPassword,
            final String newPassword, final Boolean asAdmin,
            final ResponseEvaluator bindEvaluator,
            final ResponseEvaluator modifyEvaluator ) {
        runWithConnection( new ConnectedTestCase() {
            @Override
            public void run( LdapConnection connection ) {
                LdapException exception = null;
                ResultResponse response = null;
                PasswordPolicy passwordPolicy = null;
                try {
                    if ( asAdmin ) {
                        response = authenticateAdmin( connection );
                    }
                    else {
                        response = authenticate( connection, userDn, oldPassword );
                    }
                    passwordPolicy = getPasswordPolicyResponseControl( response );
                }
                catch ( LdapException e ) {
                    exception = e;
                }
                bindEvaluator.evaluate( exception, response, passwordPolicy );

                exception = null;
                response = null;
                passwordPolicy = null;
                try {
                    response = changePassword( connection, userDn, newPassword );
                    passwordPolicy = getPasswordPolicyResponseControl( response );
                }
                catch ( LdapException e ) {
                    exception = e;
                }
                modifyEvaluator.evaluate( exception, response, passwordPolicy );
            }
        } );
    }

    private PasswordModifyResponse changePasswordWithPasswordModify( LdapConnection connection,
            Dn userDn, String oldPassword, String newPassword ) throws LdapException {
        PasswordModifyRequestImpl request = new PasswordModifyRequestImpl();
        request.setNewPassword( newPassword.getBytes( UTF_8 ) );
        if ( userDn != null ) {
            request.setUserIdentity( Dn.getBytes( userDn ) );
        }
        if ( oldPassword != null ) {
            request.setOldPassword( oldPassword.getBytes( UTF_8 ) );
        }
        request.addControl( passwordPolicyRequestControl );
        return (PasswordModifyResponse) connection.extended( request );
    }

    private void changePasswordWithPasswordModify( final Dn userDn, final String oldPassword,
            final String newPassword, final Boolean asAdmin,
            final ResponseEvaluator bindEvaluator,
            final ResponseEvaluator modifyEvaluator ) {
        runWithConnection( new ConnectedTestCase() {
            @Override
            public void run( LdapConnection connection ) {
                LdapException exception = null;
                ResultResponse response = null;
                PasswordPolicy passwordPolicy = null;
                try {
                    if ( asAdmin ) {
                        response = authenticateAdmin( connection );
                    }
                    else {
                        response = authenticate( connection, userDn, oldPassword );
                    }
                    passwordPolicy = getPasswordPolicyResponseControl( response );
                }
                catch ( LdapException e ) {
                    exception = e;
                }
                bindEvaluator.evaluate( exception, response, passwordPolicy );

                exception = null;
                response = null;
                passwordPolicy = null;
                try {
                    if ( asAdmin ) {
                        // bound by admin, so reset users password
                        response = changePasswordWithPasswordModify( connection, userDn, null, newPassword );
                    }
                    else {
                        // bound by user, so change password of bound context
                        response = changePasswordWithPasswordModify( connection, null, oldPassword, newPassword );
                    }
                    passwordPolicy = getPasswordPolicyResponseControl( response );
                }
                catch ( LdapException e ) {
                    exception = e;
                }
                modifyEvaluator.evaluate( exception, response, passwordPolicy );
            }
        } );
    }

    private void failChangePasswordInsufficientPasswordQuality( Dn dn, String oldPassword, String newPassword ) {
        changePassword( dn, oldPassword, newPassword, false,
                successNoWarningResponseEvaluator,
                newResponseEvaluator( ResultCodeEnum.CONSTRAINT_VIOLATION, PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY ) );
        authenticate( testUserDn, testUserPassword,
                successNoWarningResponseEvaluator );
    }

    private PasswordPolicy getPasswordPolicyResponseControl( Response response ) {
        Control control = response.getControls().get( passwordPolicyRequestControl.getOid() );
        if ( control == null ) {
            return null;
        }
        return ((PasswordPolicyDecorator) control).getDecorated();
    }

    @SuppressWarnings( "unused" )
    private Entry lookup( final Dn dn ) throws LdapException {
        LdapCoreSessionConnection connection = null;
        try {
            connection = new LdapCoreSessionConnection();
            connection.setDirectoryService( classCreateLdapServerRule.getDirectoryService() );
            authenticateAdmin( connection );
            return connection.lookup( dn, "*", "+" );
        }
        finally {
            if ( connection != null ) {
                try {
                    connection.close();
                }
                catch ( IOException e ) {
                    logger.warn( "possible connection leak: {}", e.getMessage() );
                    logger.debug( "possible connection leak:", e );
                }
            }
        }

    }

    private ResponseEvaluator newResponseEvaluator( final ResultCodeEnum resultCode, final PasswordPolicyErrorEnum policyError ) {
        return new ResponseEvaluator() {
            @Override
            public void evaluate( LdapException exception, ResultResponse response, PasswordPolicy passwordPolicy ) {
                assertNull( exception );
                assertEquals( resultCode, response.getLdapResult().getResultCode() );
                assertEquals( policyError, passwordPolicy.getResponse().getPasswordPolicyError() );
            }
        };
    }

    /**
     * For some reason revert is not removing stuff so we have to create and
     * destroy the test user for each case.
     * 
     * @throws Exception
     */
    @After
    public void removeTestUser() throws Exception {
        DeleteRequest deleteRequest = new DeleteRequestImpl();
        deleteRequest.setName( testUserDn );
        assertEquals( ResultCodeEnum.SUCCESS,
                getAdminNetworkConnection( classCreateLdapServerRule.getLdapServer() )
                        .delete( deleteRequest ).getLdapResult().getResultCode() );
    }

    private void runWithConnection( ConnectedTestCase testCase ) {
        LdapNetworkConnection connection = null;
        try {
            connection = new LdapNetworkConnection( "localhost", 
                    classCreateLdapServerRule.getLdapServer().getPort() );
            connection.setTimeOut( 0 );
            testCase.run( connection );
        }
        finally {
            if ( connection != null ) {
                try {
                    connection.close();
                }
                catch ( IOException e ) {
                    logger.warn( "possible connection leak: {}", e.getMessage() );
                    logger.debug( "possible connection leak:", e );
                }
            }
        }
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testFailValidatorOnlyDigits() {
        failChangePasswordInsufficientPasswordQuality(
                testUserDn, testUserPassword, "12345" );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testFailValidatorOnly2CharacterSets() {
        failChangePasswordInsufficientPasswordQuality(
                testUserDn, testUserPassword, "FOObarBAZ" );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testFailValidatorIllegalCharacter() {
        failChangePasswordInsufficientPasswordQuality( testUserDn, testUserPassword, "F00barBAZ~" );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testFailValidatorUsername() {
        failChangePasswordInsufficientPasswordQuality( testUserDn, testUserPassword, "TeStUsEr" );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testFailValidatorUsernameReverse() {
        failChangePasswordInsufficientPasswordQuality( testUserDn, testUserPassword, "rEsUtSeT" );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdMustChange = true,
            pwdMinAge = 5,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testMinAge() throws LdapException, InterruptedException {
        // allow immedate change when last set by admin
        changePassword( testUserDn, testUserPassword, "set%Daw()d", false,
                newResponseEvaluator( ResultCodeEnum.SUCCESS, PasswordPolicyErrorEnum.CHANGE_AFTER_RESET ),
                successNoWarningResponseEvaluator );

        // too early to change
        changePassword( testUserDn, "set%Daw()d", "set4Daw00d", false,
                successNoWarningResponseEvaluator,
                newResponseEvaluator( ResultCodeEnum.CONSTRAINT_VIOLATION, PasswordPolicyErrorEnum.PASSWORD_TOO_YOUNG ) );

        // wait for min age expiration
        Thread.sleep( 5000 );
        changePassword( testUserDn, "set%Daw()d", "set4Daw00d", false,
                successNoWarningResponseEvaluator,
                successNoWarningResponseEvaluator );

        // demonstrate admin can avoid waiting
        changePassword( testUserDn, "set4Daw00d", "daw00Dru1z", true,
                successNoWarningResponseEvaluator,
                successNoWarningResponseEvaluator );

        // verify final pwd
        authenticate( testUserDn, "daw00Dru1z",
                newResponseEvaluator( ResultCodeEnum.SUCCESS, PasswordPolicyErrorEnum.CHANGE_AFTER_RESET ) );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testPassPasswordModify() {
        changePasswordWithPasswordModify( testUserDn, testUserPassword, "h00zlEabc", false,
                successNoWarningResponseEvaluator,
                successNoWarningResponseEvaluator );
        authenticate( testUserDn, "h00zlEabc",
                successNoWarningResponseEvaluator );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testPassValidatorUpperLowerNonAlpha() {
        changePassword( testUserDn, testUserPassword, "set%Daw()d", false,
                successNoWarningResponseEvaluator,
                successNoWarningResponseEvaluator );
        authenticate( testUserDn, "set%Daw()d",
                successNoWarningResponseEvaluator );
    }

    @Test
    @ApplyPasswordPolicy(
            pwdValidator = PastdevPasswordValidator.class,
            pwdCheckQuality = CheckQualityEnum.CHECK_ACCEPT )
    public void testPassValidatorUpperLowerDigit() {
        changePassword( testUserDn, testUserPassword, "set4Daw00d", false,
                successNoWarningResponseEvaluator,
                successNoWarningResponseEvaluator );
        authenticate( testUserDn, "set4Daw00d",
                successNoWarningResponseEvaluator );
    }

    private interface ConnectedTestCase {
        public void run( LdapConnection connection );
    }

    private interface ResponseEvaluator {
        public void evaluate( LdapException exception, ResultResponse response, PasswordPolicy passwordPolicy );
    }
}

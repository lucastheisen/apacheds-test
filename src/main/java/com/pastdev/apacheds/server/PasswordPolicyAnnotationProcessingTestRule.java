package com.pastdev.apacheds.server;


import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.authn.ppolicy.PasswordPolicyConfiguration;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.ppolicy.PpolicyConfigContainer;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PasswordPolicyAnnotationProcessingTestRule implements TestRule {
    private static Logger logger = LoggerFactory.getLogger( PasswordPolicyAnnotationProcessingTestRule.class );

    private AuthenticationInterceptor authenticationInterceptor;

    public PasswordPolicyAnnotationProcessingTestRule( AuthenticationInterceptor authenticationInterceptor ) {
        this.authenticationInterceptor = authenticationInterceptor;
    }

    @Override
    public Statement apply( final Statement base, Description description ) {
        final ApplyPasswordPolicy applyPasswordPolicy = description.getAnnotation( ApplyPasswordPolicy.class );
        if ( applyPasswordPolicy == null ) {
            return base;
        }
        else {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    PpolicyConfigContainer originalPolicyContainer = authenticationInterceptor.getPwdPolicyContainer();

                    logger.trace( "setting password policy from method annotation" );
                    authenticationInterceptor.setPwdPolicies( getPolicyContainer( applyPasswordPolicy ) );

                    try {
                        base.evaluate();
                    }
                    finally {
                        logger.trace( "restoring original password policy" );
                        authenticationInterceptor.setPwdPolicies( originalPolicyContainer );
                    }
                }
            };
        }
    }

    PpolicyConfigContainer getPolicyContainer( ApplyPasswordPolicy applyPasswordPolicy ) throws InstantiationException, IllegalAccessException {
        PasswordPolicyConfiguration config = new PasswordPolicyConfiguration();
        config.setPwdAllowUserChange( applyPasswordPolicy.pwdAllowUserChange() );
        config.setPwdAttribute( applyPasswordPolicy.pwdAttribute() );
        config.setPwdCheckQuality( applyPasswordPolicy.pwdCheckQuality() );
        config.setPwdExpireWarning( applyPasswordPolicy.pwdExpireWarning() );
        config.setPwdFailureCountInterval( applyPasswordPolicy.pwdFailureCountInterval() );
        config.setPwdGraceAuthNLimit( applyPasswordPolicy.pwdGraceAuthNLimit() );
        config.setPwdGraceExpire( applyPasswordPolicy.pwdGraceExpire() );
        config.setPwdInHistory( applyPasswordPolicy.pwdInHistory() );
        config.setPwdLockout( applyPasswordPolicy.pwdLockout() );
        config.setPwdLockoutDuration( applyPasswordPolicy.pwdLockoutDuration() );
        config.setPwdMustChange( applyPasswordPolicy.pwdMustChange() );
        config.setPwdMaxAge( applyPasswordPolicy.pwdMaxAge() );
        config.setPwdMinAge( applyPasswordPolicy.pwdMinAge() );
        config.setPwdMaxDelay( applyPasswordPolicy.pwdMaxDelay() );
        config.setPwdMinDelay( applyPasswordPolicy.pwdMinDelay() );
        config.setPwdMaxFailure( applyPasswordPolicy.pwdMaxFailure() );
        config.setPwdMaxIdle( applyPasswordPolicy.pwdMaxIdle() );
        config.setPwdMaxLength( applyPasswordPolicy.pwdMaxLength() );
        config.setPwdMinLength( applyPasswordPolicy.pwdMinLength() );
        config.setPwdSafeModify( applyPasswordPolicy.pwdSafeModify() );
        config.setPwdValidator( applyPasswordPolicy.pwdValidator().newInstance() );
        
        Dn defaultPolicyDn;
        try {
            defaultPolicyDn = new Dn( "uid=ppolicy,dc=example,dc=com" );
        }
        catch ( LdapInvalidDnException e ) {
            throw new RuntimeException( "um, this shouldn't happen", e );
        }
        PpolicyConfigContainer container = new PpolicyConfigContainer();
        container.addPolicy( defaultPolicyDn, config );
        container.setDefaultPolicyDn( defaultPolicyDn );
        return container;
    }
}

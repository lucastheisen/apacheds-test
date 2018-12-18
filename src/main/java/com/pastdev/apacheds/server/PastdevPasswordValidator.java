package com.pastdev.apacheds.server;


import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;


import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyErrorEnum;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.server.core.api.authn.ppolicy.PasswordPolicyException;
import org.apache.directory.server.core.api.authn.ppolicy.PasswordValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import edu.vt.middleware.dictionary.ArrayWordList;
import edu.vt.middleware.dictionary.WordListDictionary;
import edu.vt.middleware.dictionary.WordLists;
import edu.vt.middleware.dictionary.sort.ArraysSort;
import edu.vt.middleware.password.CharacterCharacteristicsRule;
import edu.vt.middleware.password.CharacterRule;
import edu.vt.middleware.password.DictionarySubstringRule;
import edu.vt.middleware.password.DigitCharacterRule;
import edu.vt.middleware.password.IllegalCharacterRule;
import edu.vt.middleware.password.LowercaseCharacterRule;
import edu.vt.middleware.password.MessageResolver;
import edu.vt.middleware.password.NonAlphanumericCharacterRule;
import edu.vt.middleware.password.Password;
import edu.vt.middleware.password.PasswordData;
import edu.vt.middleware.password.Rule;
import edu.vt.middleware.password.RuleResult;
import edu.vt.middleware.password.RuleResultDetail;
import edu.vt.middleware.password.UppercaseCharacterRule;
import edu.vt.middleware.password.UsernameRule;


public class PastdevPasswordValidator implements PasswordValidator {
    private static Logger logger = LoggerFactory.getLogger( PastdevPasswordValidator.class );
    private static final String MESSAGES_PROPERTIES = "/conf/password_policy_validator_messages.properties";

    private String allowedSpecials = "!@#$%*()-=+{}:',.?/";
    private String dictionary = "cracklib-words-20080507";
    private boolean dictionaryCaseSensitive = true;
    private boolean dictionaryEnabled = false;
    private boolean dictionaryMatchBackwards = false;
    private String illegalSpecials = "`~";
    private MessageResolver messageResolver;
    private int minimumLowerCharacters = 1;
    private int minimumDigits = 1;
    private int minimumSpecialCharacters = 1;
    private int minimumUpperCharacters = 1;
    private int minimumCharacterTypes = 3;
    private boolean usernameCaseSensitive = false;
    private boolean usernameMatchBackwards = true;
    private edu.vt.middleware.password.PasswordValidator validator;

    public PastdevPasswordValidator() {}

    /**
     * Returns a {@link edu.vt.middleware.password.PasswordValidator
     * PasswordValidator} that satisfies Pastdev rules. Pastdev
     * requires:
     * 
     * Passwords must be a minimum of eight (8) characters and minimally contain
     * 3 of the 4 following character types;
     * 
     * <ul>
     * <li>English upper case letters (e.g., A, B, C, ...Z)</li>
     * <li>English lower case letters (e.g., a, b, c, ...z)</li>
     * <li>Westernized Arabic numerals (e.g., 1, 1, 2, ...9)</li>
     * <li>Non-alphanumeric ("special characters) (e.g., ?,!,%,$,#, etc)</li>
     * </ul>
     * 
     * Passwords must not include dictionary words, common names or
     * account-related information.
     * 
     * <em>Note: password length is handled by apache directory password policy</em>
     * 
     * @throws IOException
     */
    edu.vt.middleware.password.PasswordValidator getValidator() {
        if ( validator == null ) {
            // lazy initialize to ensure injection occurs beforehand
            List<Rule> ruleList = new ArrayList<Rule>();

            // character complexity
            PastdevCharacterCharacteristicsRule charRule = new PastdevCharacterCharacteristicsRule();
            charRule.getRules().add( new PastdevUppercaseCharacterRule( minimumUpperCharacters ) );
            charRule.getRules().add( new PastdevLowercaseCharacterRule( minimumLowerCharacters ) );
            charRule.getRules().add( new PastdevDigitCharacterRule( minimumDigits ) );
            charRule.getRules().add( new PastdevNonAlphanumericCharacterRule( minimumSpecialCharacters ) );
            charRule.setNumberOfCharacteristics( minimumCharacterTypes );
            ruleList.add( charRule );

            // illegal characters
            ruleList.add( new IllegalCharacterRule( illegalSpecials.toCharArray() ) );

            // dictionary words and common names
            if ( dictionaryEnabled ) {
                try {
                    DictionarySubstringRule dictRule = new DictionarySubstringRule(
                            new WordListDictionary( getWordList() ) );
                    dictRule.setWordLength( 4 );
                    dictRule.setMatchBackwards( dictionaryMatchBackwards );
                    ruleList.add( dictRule );

                }
                catch ( IOException e ) {
                    throw new IllegalStateException( "Unable to load dictionary", e );
                }
            }

            ruleList.add( new UsernameRule( usernameMatchBackwards, !usernameCaseSensitive ) );

            InputStream inputStream = null;
            try {
                inputStream = PastdevPasswordValidator.class.getResourceAsStream( MESSAGES_PROPERTIES );
                Properties messages = new Properties();
                messages.load( inputStream );
                messageResolver = new MessageResolver( messages );
            }
            catch ( IOException e ) {
                // accept default messages
                messageResolver = new MessageResolver();
            }
            finally {
                if ( inputStream != null ) {
                    try {
                        inputStream.close();
                    }
                    catch ( IOException e ) {
                        // ignore
                    }
                }
            }
            validator = new edu.vt.middleware.password.PasswordValidator( messageResolver, ruleList );
        }

        return validator;
    }

    private ArrayWordList getWordList() throws IOException {
        return WordLists.createFromReader(
                new Reader[] { new InputStreamReader( getClass().getClassLoader().getResourceAsStream( dictionary ) ) },
                dictionaryCaseSensitive,
                new ArraysSort() );
    }

    public void setAllowedSpecial( String allowedSpecials ) {
        this.allowedSpecials = allowedSpecials;
    }
    
    public void setDictionaryEnabled( boolean enabled ) {
        this.dictionaryEnabled = enabled;
    }

    public void setMinimumCharacterTypes( int minimumCharacterTypes ) {
        this.minimumCharacterTypes = minimumCharacterTypes;
    }

    public void setMinimumLowerCharacters( int lowerCount ) {
        this.minimumLowerCharacters = lowerCount;
    }

    public void setMinimumDigits( int digitCount ) {
        this.minimumDigits = digitCount;
    }

    public void setMinimumSpecialCharacters( int specialCount ) {
        this.minimumSpecialCharacters = specialCount;
    }

    public void setMinimumUpper( int upperCount ) {
        this.minimumUpperCharacters = upperCount;
    }

    @Override
    public void validate( String password, Entry user ) throws PasswordPolicyException {
        String username = null;
        try {
            String email = user.get( "mail" ).getString();
            int atIndex = email.indexOf( '@' );
            username = email.substring( 0, atIndex );
        }
        catch ( LdapInvalidAttributeValueException e ) {
            throw new PasswordPolicyException( "Email not found for '" + user.getDn() + "'" );
        }

        validate( password, username );
    }

    void validate( String password, String username ) throws PasswordPolicyException {
        PasswordData passwordData = new PasswordData( new Password( password ) );
        passwordData.setUsername( username );
        RuleResult result = getValidator().validate( passwordData );

        if ( !result.isValid() ) {
            String detailMessage = null;
            for ( RuleResultDetail detail : result.getDetails() ) {
                String tempMessage = messageResolver.resolve( detail );
                logger.debug( "Invalid password: {}", tempMessage );

                String errorCode = detail.getErrorCode();
                if ( CharacterCharacteristicsRule.ERROR_CODE.equals( errorCode ) ) {
                    detailMessage = tempMessage;
                }
                else if ( detailMessage == null ) {
                    detailMessage = tempMessage;
                }
            }
            throw new PasswordPolicyException( detailMessage,
                    PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY
                            .getValue() );
        }
    }

    private interface PastdevCharacterRule extends CharacterRule {
        public String getCharacterType();
    }

    private class PastdevCharacterCharacteristicsRule extends CharacterCharacteristicsRule {
        @Override
        protected Map<String, ?> createRuleResultDetailParameters( final int success ) {
            @SuppressWarnings( "unchecked" )
            Map<String, Object> m = (Map<String, Object>) super.createRuleResultDetailParameters( success );
            StringBuilder builder = null;
            for ( CharacterRule rule : getRules() ) {
                if ( builder == null ) {
                    builder = new StringBuilder();
                }
                else {
                    builder.append( ", " );
                }

                if ( rule instanceof PastdevCharacterRule ) {
                    builder.append( ((PastdevCharacterRule) rule).getCharacterType() );
                }
                else {
                    builder.append( rule.getClass().getName() );
                }
            }
            m.put( "characterSets", builder.toString() );
            return m;
        }
    }

    private class PastdevDigitCharacterRule
            extends DigitCharacterRule implements PastdevCharacterRule {
        private PastdevDigitCharacterRule( int minimum ) {
            super( minimum );
        }

        @Override
        public String getCharacterType() {
            return super.getCharacterType();
        }
    }

    private class PastdevLowercaseCharacterRule
            extends LowercaseCharacterRule implements PastdevCharacterRule {
        private PastdevLowercaseCharacterRule( int minimum ) {
            super( minimum );
        }

        @Override
        public String getCharacterType() {
            return super.getCharacterType();
        }
    }

    private class PastdevNonAlphanumericCharacterRule
            extends NonAlphanumericCharacterRule implements PastdevCharacterRule {
        private PastdevNonAlphanumericCharacterRule( int minimum ) {
            super( minimum );
        }

        @Override
        public String getCharacterType() {
            return super.getCharacterType();
        }

        /** {@inheritDoc} */
        @Override
        public String getValidCharacters() {
            return allowedSpecials;
        }
    }

    private class PastdevUppercaseCharacterRule
            extends UppercaseCharacterRule implements PastdevCharacterRule {
        private PastdevUppercaseCharacterRule( int minimum ) {
            super( minimum );
        }

        @Override
        public String getCharacterType() {
            return super.getCharacterType();
        }
    }
}

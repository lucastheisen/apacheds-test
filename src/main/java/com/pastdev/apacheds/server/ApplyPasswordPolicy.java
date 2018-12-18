package com.pastdev.apacheds.server;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


import org.apache.directory.server.core.api.authn.ppolicy.CheckQualityEnum;
import org.apache.directory.server.core.api.authn.ppolicy.DefaultPasswordValidator;
import org.apache.directory.server.core.api.authn.ppolicy.PasswordValidator;

@Retention( RetentionPolicy.RUNTIME )
@Target(
{ ElementType.METHOD } )
public @interface ApplyPasswordPolicy {
    boolean pwdAllowUserChange() default true;

    String pwdAttribute() default "userPassword";

    CheckQualityEnum pwdCheckQuality() default CheckQualityEnum.NO_CHECK;

    int pwdExpireWarning() default 0;

    int pwdFailureCountInterval() default 0;

    int pwdGraceAuthNLimit() default 0;

    int pwdGraceExpire() default 0;

    int pwdInHistory() default 0;

    boolean pwdLockout() default false;

    int pwdLockoutDuration() default 0;

    boolean pwdMustChange() default false;

    int pwdMaxAge() default 0;

    int pwdMinAge() default 0;

    int pwdMaxDelay() default 0;

    int pwdMinDelay() default 0;

    int pwdMaxFailure() default 0;

    int pwdMaxIdle() default 0;

    int pwdMaxLength() default -1;

    int pwdMinLength() default 0;

    boolean pwdSafeModify() default false;

    Class<? extends PasswordValidator> pwdValidator() default DefaultPasswordValidator.class;
}

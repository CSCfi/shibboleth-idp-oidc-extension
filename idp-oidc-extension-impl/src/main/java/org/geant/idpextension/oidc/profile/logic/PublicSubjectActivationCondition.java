package org.geant.idpextension.oidc.profile.logic;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.nimbusds.openid.connect.sdk.SubjectType;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** Activation condition returning true if public subject is requested. */
@SuppressWarnings("rawtypes")
public class PublicSubjectActivationCondition implements Predicate<ProfileRequestContext> {
    
    /** Strategy used to obtain subject type. */
    @Nonnull
    protected Function<ProfileRequestContext, SubjectType> subjectTypeLookupStrategy;
    
    /**
     * Constructor.
     */
    public PublicSubjectActivationCondition() {
        subjectTypeLookupStrategy = new DefaultSubjectTypeStrategy();
    }
    
    /**
     * Set the strategy used to locate subject type.
     * 
     * @param strategy lookup strategy
     */
    public void setSubjectTypeLookupStrategy(@Nonnull final Function<ProfileRequestContext, SubjectType> strategy) {
        subjectTypeLookupStrategy =
                Constraint.isNotNull(strategy, "SubjectTypeLookupStrategy lookup strategy cannot be null");
    }
    
    @Override
    public boolean apply(ProfileRequestContext input) {
        return SubjectType.PUBLIC.equals(subjectTypeLookupStrategy.apply(input));
    }
}



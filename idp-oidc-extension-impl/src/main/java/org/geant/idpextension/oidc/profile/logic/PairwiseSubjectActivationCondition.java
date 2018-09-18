package org.geant.idpextension.oidc.profile.logic;

import org.opensaml.profile.context.ProfileRequestContext;
import com.nimbusds.openid.connect.sdk.SubjectType;

/** Activation condition returning true if pairwise subject is requested. */
@SuppressWarnings("rawtypes")
public class PairwiseSubjectActivationCondition extends PublicSubjectActivationCondition {

    @Override
    public boolean apply(ProfileRequestContext input) {
        return SubjectType.PAIRWISE.equals(subjectTypeLookupStrategy.apply(input));
    }
}



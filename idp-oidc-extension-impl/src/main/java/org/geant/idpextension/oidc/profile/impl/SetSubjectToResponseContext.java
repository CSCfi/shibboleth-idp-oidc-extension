/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.profile.impl;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestSubjectLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.SubjectType;

/**
 * Action that locates subject using strategy. Located subject is set to {@link OIDCAuthenticationResponseContext}.
 **/
@SuppressWarnings("rawtypes")
public class SetSubjectToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetSubjectToResponseContext.class);

    /** Strategy used to obtain the subject. */
    @Nonnull
    private Function<ProfileRequestContext, String> subjectLookupStrategy;

    /** Strategy used to determine the subject type to try. */
    @Nonnull
    private Function<ProfileRequestContext, SubjectType> subjectTypeStrategy;

    /** Subject type. */
    @Nonnull
    @NonnullElements
    private SubjectType subjectType;

    /**
     * Set the strategy function to use to obtain the subject type.
     * 
     * @param strategy subject type lookup strategy
     */
    public void setSubjectTypeLookupStrategy(@Nonnull final Function<ProfileRequestContext, SubjectType> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        subjectTypeStrategy = Constraint.isNotNull(strategy, "Subject type lookup strategy cannot be null");
    }

    /**
     * Constructor.
     */
    public SetSubjectToResponseContext() {
        subjectLookupStrategy = new TokenRequestSubjectLookupFunction();
    }

    /**
     * Set the strategy used to locate subject.
     * 
     * @param strategy lookup strategy
     */
    public void setSubjectLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        subjectLookupStrategy = Constraint.isNotNull(strategy, "SubjectLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        String subject = subjectLookupStrategy.apply(profileRequestContext);
        if (subject == null) {
            log.error("{} Subject may not be null", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        getOidcResponseContext().setSubject(subject);
        if (subjectTypeStrategy != null) {
            getOidcResponseContext()
                    .setSubjectType(SubjectType.PUBLIC.equals(subjectTypeStrategy.apply(profileRequestContext))
                            ? "public" : "pairwise");
        }
    }

}
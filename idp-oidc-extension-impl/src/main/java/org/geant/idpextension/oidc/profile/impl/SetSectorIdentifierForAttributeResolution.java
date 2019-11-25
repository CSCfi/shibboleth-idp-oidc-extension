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
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.profile.context.navigate.SectorIdentifierLookupFunction;
import org.geant.idpextension.oidc.profile.logic.DefaultSubjectTypeStrategy;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.SubjectType;

/**
 * An action that sets {@link AttributeResolutionContext#setAttributeRecipientGroupID} to sector identifier if pairwise
 * subject is requested. This values is later used by computed id generation. If public subject is requested, then a
 * shared value is used instead of sector identifier.
 */
@SuppressWarnings("rawtypes")
public class SetSectorIdentifierForAttributeResolution extends AbstractOIDCAuthenticationRequestAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SetSectorIdentifierForAttributeResolution.class);

    /** Strategy used to obtain sector identifier. */
    @Nonnull
    private Function<ProfileRequestContext, String> sectorIdentifierLookupStrategy;

    /** Strategy used to obtain subject type. */
    @Nonnull
    private Function<ProfileRequestContext, SubjectType> subjectTypeLookupStrategy;

    /**
     * Constructor.
     */
    public SetSectorIdentifierForAttributeResolution() {
        sectorIdentifierLookupStrategy = new SectorIdentifierLookupFunction();
        subjectTypeLookupStrategy = new DefaultSubjectTypeStrategy();
    }

    /**
     * Set the strategy used to locate sector identifier.
     * 
     * @param strategy lookup strategy
     */
    public void setSectorIdentifierLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        sectorIdentifierLookupStrategy =
                Constraint.isNotNull(strategy, "SectorIdentifierLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate subject type.
     * 
     * @param strategy lookup strategy
     */
    public void setSubjectTypeLookupStrategy(@Nonnull final Function<ProfileRequestContext, SubjectType> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        subjectTypeLookupStrategy =
                Constraint.isNotNull(strategy, "SubjectTypeLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (SubjectType.PUBLIC.equals(subjectTypeLookupStrategy.apply(profileRequestContext))) {
            ((AttributeResolutionContext) profileRequestContext.getSubcontext(AttributeResolutionContext.class, true))
                    .setAttributeRecipientGroupID("public");
            log.debug("{} Attribute recipient group id set to value public for generating subject of type public",
                    getLogPrefix());
            return;
        }
        String sectorIdentifier = sectorIdentifierLookupStrategy.apply(profileRequestContext);
        if (sectorIdentifier == null) {
            log.error("{} No sector identifier, pairwise subject cannot be generated", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.MISSING_REDIRECT_URIS);
            return;
        }
        ((AttributeResolutionContext) profileRequestContext.getSubcontext(AttributeResolutionContext.class, true))
                .setAttributeRecipientGroupID(sectorIdentifier);
        log.debug(
                "{} Attribute recipient group id set to sector identifier value {} for generating subject of type pairwise",
                getLogPrefix(), sectorIdentifier);
    }

}
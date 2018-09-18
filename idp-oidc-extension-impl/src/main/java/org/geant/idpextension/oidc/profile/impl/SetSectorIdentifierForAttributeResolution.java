/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.profile.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.profile.context.navigate.SectorIdentifierLookupFunction;
import org.geant.idpextension.oidc.profile.logic.DefaultSubjectTypeStrategy;
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

    /** Sector identifier. */
    @Nullable
    private String sectorIdentifier;

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
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        sectorIdentifier = sectorIdentifierLookupStrategy.apply(profileRequestContext);
        if (sectorIdentifier == null) {
            log.warn("{} No sector identifier, nothing to do", getLogPrefix());
            return false;
        }
        return super.doPreExecute(profileRequestContext);
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
        ((AttributeResolutionContext) profileRequestContext.getSubcontext(AttributeResolutionContext.class, true))
                .setAttributeRecipientGroupID(sectorIdentifier);
        log.debug(
                "{} Attribute recipient group id set to sector identifier value {} for generating subject of type pairwise",
                getLogPrefix(), sectorIdentifier);
    }

}
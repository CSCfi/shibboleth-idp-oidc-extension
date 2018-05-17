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

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.profile.SAML2NameIDGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.SubjectType;

/**
 * Uses saml2 name id generator to form name id for response context.
 * 
 * Based on shibboleth class implementing same for SAML2.
 *
 */
@SuppressWarnings("rawtypes")
public class SetNameIDToResponseContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetNameIDToResponseContext.class);

    /** Generator to use. */
    @NonnullAfterInit
    private SAML2NameIDGenerator generator;

    /** Strategy used to determine the subject type to try. */
    @Nonnull
    private Function<ProfileRequestContext, SubjectType> subjectTypeStrategy;

    /** Subject type. */
    @Nonnull
    @NonnullElements
    private SubjectType subjectType;

    /**
     * Set the generator to use.
     * 
     * @param theGenerator the generator to use
     */
    public void setNameIDGenerator(@Nullable final SAML2NameIDGenerator theGenerator) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        generator = Constraint.isNotNull(theGenerator, "SAML2NameIDGenerator cannot be null");
    }

    /**
     * Set the strategy function to use to obtain the subject type.
     * 
     * @param strategy subject type lookup strategy
     */
    public void setSubjectTypeLookupStrategy(@Nonnull final Function<ProfileRequestContext, SubjectType> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        subjectTypeStrategy = Constraint.isNotNull(strategy, "Subject type lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (generator == null) {
            throw new ComponentInitializationException("SAML2NameIDGenerator cannot be null");
        }
        if (subjectTypeStrategy == null) {
            throw new ComponentInitializationException("Subject type lookup strategy cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        subjectType = subjectTypeStrategy.apply(profileRequestContext);
        if (subjectType == null) {
            log.error("{} No oidc subject identifier type defined", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);

    }

    /**
     * Attempt to generate a {@link NameID} using each of the candidate and plugins.
     * 
     * @param profileRequestContext current profile request context
     * 
     * @return a generated {@link NameID} or null
     */
    @Nullable
    private NameID generateNameID(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("{} Trying to generate Subject with Type {}", getLogPrefix(), subjectType.toString());
        try {
            final NameID nameId = generator.generate(profileRequestContext, subjectType.toString());
            if (nameId != null) {
                log.debug("{} Successfully generated Subject with Type {}", getLogPrefix(), subjectType.toString());
                return nameId;
            }
        } catch (final SAMLException e) {
            log.error("{} Error while generating Subject", getLogPrefix(), e);
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final NameID nameId = generateNameID(profileRequestContext);
        if (nameId == null) {
            log.error("{} Subject may not be null", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        getOidcResponseContext().setSubject(nameId.getValue());
        log.debug("{} Subject of type {} set to {}", getLogPrefix(), nameId.getFormat(), nameId.getValue());

    }

}
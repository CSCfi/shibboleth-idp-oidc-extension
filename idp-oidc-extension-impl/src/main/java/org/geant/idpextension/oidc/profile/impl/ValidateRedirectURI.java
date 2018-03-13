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

import java.net.URI;
import java.util.Set;
import javax.annotation.Nonnull;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRedirectURILookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultValidRedirectUrisLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that validates redirect uri is a expected one. Validated redirect uri is stored to response context.
 */
@SuppressWarnings("rawtypes")
public class ValidateRedirectURI extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateRedirectURI.class);

    /** Strategy used to obtain the redirect uri value in request. */
    @Nonnull
    private Function<ProfileRequestContext, URI> redirectURILookupStrategy;

    /** Strategy used to obtain the redirect uris to compare request value to. */
    @Nonnull
    private Function<ProfileRequestContext, Set<URI>> validRedirectURIsLookupStrategy;

    /**
     * Constructor.
     */
    public ValidateRedirectURI() {
        redirectURILookupStrategy = new DefaultRedirectURILookupFunction();
        validRedirectURIsLookupStrategy = new DefaultValidRedirectUrisLookupFunction();
    }

    /**
     * Set the strategy used to locate the redirect uri of the request.
     * 
     * @param strategy lookup strategy
     */
    public void setRedirectURILookupStrategy(@Nonnull final Function<ProfileRequestContext, URI> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        redirectURILookupStrategy =
                Constraint.isNotNull(strategy, "RedirectURILookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the redirect uris to compare against.
     * 
     * @param strategy lookup strategy
     */
    public void setValidRedirectURIsLookupStrategy(@Nonnull final Function<ProfileRequestContext, Set<URI>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        validRedirectURIsLookupStrategy =
                Constraint.isNotNull(strategy, "ValidRedirectURIsLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<URI> redirectionURIs = validRedirectURIsLookupStrategy.apply(profileRequestContext);
        URI requestRedirectURI = redirectURILookupStrategy.apply(profileRequestContext);
        if (requestRedirectURI != null && redirectionURIs != null && redirectionURIs.contains(requestRedirectURI)) {
            getOidcResponseContext().setRedirectURI(requestRedirectURI);
            log.debug("{} redirect uri validated {}", getLogPrefix(), requestRedirectURI);
            return;
        }
        log.error("{} redirect uri must be validated to form response", getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URI);
        return;
    }
}
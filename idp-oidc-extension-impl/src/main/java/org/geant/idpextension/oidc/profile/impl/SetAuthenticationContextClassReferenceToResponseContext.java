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
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.principal.DefaultPrincipalDeterminationStrategy;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;

/**
 * Action that sets authentication context class reference to work context {@link OIDCAuthenticationResponseContext}
 * located under {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 */
@SuppressWarnings("rawtypes")
public class SetAuthenticationContextClassReferenceToResponseContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetAuthenticationContextClassReferenceToResponseContext.class);

    /** requested principal context. */
    @Nullable
    private RequestedPrincipalContext requestedPrincipalContext;

    /** Strategy used to determine the AuthnContextClassRef. */
    @NonnullAfterInit
    private Function<ProfileRequestContext, AuthenticationContextClassReferencePrincipal> classRefLookupStrategy;

    /**
     * Set the strategy function to use to obtain the authentication context class reference to use.
     * 
     * @param strategy authentication context class reference lookup strategy
     */
    public void setClassRefLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AuthenticationContextClassReferencePrincipal> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        classRefLookupStrategy =
                Constraint.isNotNull(strategy, "Authentication context class reference strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (classRefLookupStrategy == null) {
            classRefLookupStrategy =
                    new DefaultPrincipalDeterminationStrategy<>(AuthenticationContextClassReferencePrincipal.class,
                            new AuthenticationContextClassReferencePrincipal(
                                    AuthenticationContextClassReferencePrincipal.UNSPECIFIED));
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        AuthenticationContext authCtx = profileRequestContext.getSubcontext(AuthenticationContext.class, false);
        if (authCtx == null) {
            log.error("{} No authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        requestedPrincipalContext = authCtx.getSubcontext(RequestedPrincipalContext.class);
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        String name = null;
        if (requestedPrincipalContext != null && requestedPrincipalContext.getMatchingPrincipal() != null
                && requestedPrincipalContext
                        .getMatchingPrincipal() instanceof AuthenticationContextClassReferencePrincipal) {
            name = requestedPrincipalContext.getMatchingPrincipal().getName();
            log.debug("{} Setting acr based on requested ctx", getLogPrefix());
        } else {
            name = classRefLookupStrategy.apply(profileRequestContext).getName();
            log.debug("{} Setting acr based on performed flow", getLogPrefix());
        }
        if (name != null && !name.equals(AuthenticationContextClassReferencePrincipal.UNSPECIFIED)) {
            getOidcResponseContext().setAcr(name);
            log.debug("{} Setting acr to {}", getLogPrefix(), name);
        }
    }

}
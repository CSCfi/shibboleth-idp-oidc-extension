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

import java.security.Principal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.PreferredPrincipalContext;
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

    /** Authentication context. */
    private AuthenticationContext authCtx;

    /** requested principal context. */
    @Nullable
    private RequestedPrincipalContext requestedPrincipalContext;

    /** preferred principal context. */
    @Nullable
    private PreferredPrincipalContext preferredPrincipalContext;

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

        authCtx = profileRequestContext.getSubcontext(AuthenticationContext.class, false);
        if (authCtx == null) {
            log.error("{} No authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        requestedPrincipalContext = authCtx.getSubcontext(RequestedPrincipalContext.class);
        preferredPrincipalContext = authCtx.getSubcontext(PreferredPrincipalContext.class);
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
        } else if (preferredPrincipalContext != null && authCtx.getAuthenticationResult() != null) {
            for (Principal acr : preferredPrincipalContext.getPreferredPrincipals()) {
                if (authCtx.getAuthenticationResult()
                        .getSupportedPrincipals(AuthenticationContextClassReferencePrincipal.class).contains(acr)) {
                    name = acr.getName();
                    log.debug("{} Setting acr based on preferred ctx", getLogPrefix());
                    break;
                }
            }
        }
        if (name == null) {
            name = classRefLookupStrategy.apply(profileRequestContext).getName();
            log.debug("{} Setting acr based on performed flow", getLogPrefix());
        }
        if (name != null && !name.equals(AuthenticationContextClassReferencePrincipal.UNSPECIFIED)) {
            getOidcResponseContext().setAcr(name);
            log.debug("{} Setting acr to {}", getLogPrefix(), name);
        }
    }

}
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

import java.net.URI;
import java.util.Set;
import javax.annotation.Nonnull;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestRedirectURILookupFunction;
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
        redirectURILookupStrategy = new DefaultRequestRedirectURILookupFunction();
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
        URI requestRedirectURI = redirectURILookupStrategy.apply(profileRequestContext);
        if (requestRedirectURI == null) {
            log.error("{} Redirection URI of the request not located for verification", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URI);
        }
        final Set<URI> redirectionURIs = validRedirectURIsLookupStrategy.apply(profileRequestContext);
        if (redirectionURIs == null || redirectionURIs.isEmpty()) {
            log.error("{} Client has not registered Redirection URIs. Redirection URI cannot be validated.", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URI);
        }
        if (redirectionURIs.contains(requestRedirectURI)) {
            getOidcResponseContext().setRedirectURI(requestRedirectURI);
            log.debug("{} Redirection URI validated {}", getLogPrefix(), requestRedirectURI);
            return;
        }
        String registered = "";
        for (URI uri : redirectionURIs) {
            registered += registered.isEmpty() ? uri.toString() : ", " + uri.toString();
        }
        log.error("{} Redirection URI {} not matching any of the registered Redirection URIs [{}] ", getLogPrefix(),
                requestRedirectURI.toString(), registered);
        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URI);
        return;
    }
}
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

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.PreferredPrincipalContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import org.geant.idpextension.oidc.config.navigate.AcrClaimAlwaysEssentialLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedAcrLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * An action that creates an {@link RequestedPrincipalContext} or {@link PreferredPrincipalContext} and attaches it to
 * the current {@link AuthenticationContext}.
 * 
 * <p>
 * If the incoming message contains acr values we create principal context populated with matching
 * {@link AuthenticationContextClassReferencePrincipal}.
 * 
 * Acr values may be be given in acr_values request parameter or as requested id token
 * claim (acr) in requested claims parameter. If they are given in both, the outcome is unspecified.
 * 
 * Essential acrs are set to {@link RequestedPrincipalContext} and non-essential ones to
 * {@link PreferredPrincipalContext}.
 * </p>
 */
@SuppressWarnings("rawtypes")
public class ProcessRequestedAuthnContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ProcessRequestedAuthnContext.class);

    /** Authentication context. */
    private AuthenticationContext authenticationContext;

    /** Strategy used to obtain the requested acr values. */
    @Nonnull
    private Function<ProfileRequestContext, List<ACR>> acrLookupStrategy;
    
    /** Strategy used to obtain whether all arc claims requests should be treated as Essential. */
    @Nonnull
    private Function<ProfileRequestContext, Boolean> acrAlwaysEssentialLookupStrategy;

    /** acr values. */
    private List<ACR> acrValues;

    /** requested acr claim. */
    private Entry acrClaim;

    /**
     * Constructor.
     */
    public ProcessRequestedAuthnContext() {
        acrLookupStrategy = new DefaultRequestedAcrLookupFunction();
        acrAlwaysEssentialLookupStrategy = new AcrClaimAlwaysEssentialLookupFunction();
    }

    /**
     * Set the strategy used to locate the requested acr values.
     * 
     * @param strategy lookup strategy
     */
    public void setAcrLookupStrategy(@Nonnull final Function<ProfileRequestContext, List<ACR>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        acrLookupStrategy = Constraint.isNotNull(strategy, "AcrLookupStrategy lookup strategy cannot be null");
    }
    
    /**
     * Set the strategy used to obtain whether all arc claims requests should be treated as Essential.
     * 
     * @param strategy lookup strategy
     */
    public void setAcrAlwaysEssentialLookupStrategy(@Nonnull final Function<ProfileRequestContext, Boolean> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        acrAlwaysEssentialLookupStrategy = Constraint.isNotNull(strategy, "AcrAlwaysEssentialLookupStrategy lookup strategy cannot be null");
    }

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        acrValues = acrLookupStrategy.apply(profileRequestContext);
        if (getOidcResponseContext().getRequestedClaims() != null
                && getOidcResponseContext().getRequestedClaims().getIDTokenClaims() != null) {
            for (Entry entry : getOidcResponseContext().getRequestedClaims().getIDTokenClaims()) {
                if (IDTokenClaimsSet.ACR_CLAIM_NAME.equals(entry.getClaimName())) {
                    acrClaim = entry;
                    break;
                }
            }
        }
        if ((acrValues == null || acrValues.isEmpty())
                && (acrClaim == null || (acrClaim.getValues() == null && acrClaim.getValue() == null))) {
            log.debug("No acr values nor acr claim values in request, nothing to do");
            return false;
        }
        authenticationContext = profileRequestContext.getSubcontext(AuthenticationContext.class, false);
        if (authenticationContext == null) {
            log.error("{} No authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }
    // Checkstyle: CyclomaticComplexity ON

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final List<Principal> principals = new ArrayList<>();
        boolean isEssential = false;
        if (acrValues != null && !acrValues.isEmpty()) {
            for (ACR acr : acrValues) {
                log.debug("{} Located acr value {} in request", getLogPrefix(), acr.getValue());
                principals.add(new AuthenticationContextClassReferencePrincipal(acr.getValue()));
            }
        } else if (acrClaim != null && acrClaim.getValue() != null) {
            isEssential = acrClaim.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL);
            log.debug("{} Located {} acr claim {} in id token section of claims request", getLogPrefix(),
                    acrClaim.getClaimRequirement().toString(), acrClaim.getValue());
            principals.add(new AuthenticationContextClassReferencePrincipal(acrClaim.getValue()));
        } else if (acrClaim != null && !(acrClaim.getValues() != null && acrClaim.getValues().isEmpty())) {
            isEssential = acrClaim.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL);
            for (String acr : acrClaim.getValues()) {
                log.debug("{} Located {} acr claim {} in id token section of claims request", getLogPrefix(),
                        acrClaim.getClaimRequirement().toString(), acr);
                principals.add(new AuthenticationContextClassReferencePrincipal(acr));
            }
        }
        if (principals.isEmpty()) {
            log.debug("{} request did not contain any acr values, nothing to do", getLogPrefix());
            return;
        }
        if (isEssential || acrAlwaysEssentialLookupStrategy.apply(profileRequestContext)) {
            final RequestedPrincipalContext rpCtx = new RequestedPrincipalContext();
            rpCtx.setOperator(AuthnContextComparisonTypeEnumeration.EXACT.toString());
            rpCtx.setRequestedPrincipals(principals);
            authenticationContext.addSubcontext(rpCtx, true);
            log.debug("{} Created requested principal context", getLogPrefix());
            return;
        }
        final PreferredPrincipalContext ppCtx = new PreferredPrincipalContext();
        ppCtx.setPreferredPrincipals(principals);
        authenticationContext.addSubcontext(ppCtx, true);
        log.debug("{} Created preferred principal context", getLogPrefix());
    }
    // Checkstyle: CyclomaticComplexity ON

}
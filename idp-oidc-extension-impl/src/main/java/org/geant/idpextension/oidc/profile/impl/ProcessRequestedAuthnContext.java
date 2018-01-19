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
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;

import org.geant.idpextension.oidc.authn.principal.AuthenticationContextClassReferencePrincipal;
import org.geant.idpextension.oidc.messaging.context.OIDCRequestedPrincipalContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * An action that creates an {@link RequestedPrincipalContext} and attaches it
 * to the current {@link AuthenticationContext}.
 * 
 * <p>
 * If the incoming message contains acr values we create requested principal
 * context populated with matching
 * {@AuthenticationContextClassReferencePrincipal
 * 
 * 
 * }.
 * 
 * Acr values may be be given as authentication request parameter (acr_values)
 * or as requested id token claim (acr) in requested claims parameter. If they
 * are given in both, the outcome is unspecified.
 * 
 * </p>
 */
@SuppressWarnings("rawtypes")
public class ProcessRequestedAuthnContext extends AbstractOIDCAuthenticationRequestAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ProcessRequestedAuthnContext.class);

    /** Authentication context. */
    private AuthenticationContext authenticationContext;

    /** acr values parameter. */
    private List<ACR> acrValues;
    /** requested acr claim. */
    private Entry acrClaim;

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        acrValues = getAuthenticationRequest().getACRValues();
        if (getAuthenticationRequest().getClaims() != null
                && getAuthenticationRequest().getClaims().getIDTokenClaims() != null) {
            for (Entry entry : getAuthenticationRequest().getClaims().getIDTokenClaims()) {
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
            log.debug("{} Located {} acr claim {} in id token of request", getLogPrefix(),
                    acrClaim.getClaimRequirement().toString(), acrClaim.getValue());
            principals.add(new AuthenticationContextClassReferencePrincipal(acrClaim.getValue()));
        } else if (acrClaim != null && !(acrClaim.getValues() != null && acrClaim.getValues().isEmpty())) {
            isEssential = acrClaim.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL);
            for (String acr : acrClaim.getValues()) {
                log.debug("{} Located {} acr claim {} in id token of request", getLogPrefix(),
                        acrClaim.getClaimRequirement().toString(), acr);
                principals.add(new AuthenticationContextClassReferencePrincipal(acr));
            }
        }
        if (principals.isEmpty()) {
            log.debug("{} request did not contain any acr values, nothing to do", getLogPrefix());
            return;
        }
        final RequestedPrincipalContext rpCtx = new RequestedPrincipalContext();
        rpCtx.setOperator(AuthnContextComparisonTypeEnumeration.EXACT.toString());
        rpCtx.setRequestedPrincipals(principals);
        // we need oidc context for storing essential flag
        final OIDCRequestedPrincipalContext oidcRPCtx = authenticationContext
                .getSubcontext(OIDCRequestedPrincipalContext.class, true);
        oidcRPCtx.setEssential(isEssential);
        authenticationContext.addSubcontext(rpCtx, true);
        log.debug("{} Created requested principal context", getLogPrefix());
    }

}
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

import java.util.Date;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.jwt.JWTClaimsSet;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import org.opensaml.profile.action.ActionSupport;

import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Action that creates a Authorization Code, and sets it to work context
 * {@link OIDCAuthenticationResponseContext#getAuthorizationCode()} located
 * under {@link ProfileRequestContext#getOutboundMessageContext()}. The code is
 * not created if the requested response type equals to "id_token".
 *
 */
@SuppressWarnings("rawtypes")
public class SetAuthorizationCodeToResponseContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetAuthorizationCodeToResponseContext.class);

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** Authorization code expiration time, defaults to 10min */
    private long authCodeExp = 600000;

    /** Data sealer for handling authorization code. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Constructor.
     */
    public SetAuthorizationCodeToResponseContext(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        issuerLookupStrategy = new ResponderIdLookupFunction();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    /**
     * Set authorization code expiration time.
     * 
     * @param exp
     *            authorization code expiration time
     */
    public void setAuthCodeExp(long exp) {
        authCodeExp = exp;
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!getAuthenticationRequest().getResponseType().impliesImplicitFlow()) {
            Date dateNow = new Date();
            Date dateExp = new Date(dateNow.getTime() + authCodeExp);
            JWTClaimsSet authzCodeClaims = new JWTClaimsSet.Builder()
                    .audience(getAuthenticationRequest().getClientID().getValue())
                    .subject(subjectCtx.getPrincipalName()).issuer(issuerLookupStrategy.apply(profileRequestContext))
                    .issueTime(dateNow).expirationTime(dateExp)
                    // TODO: scope and claims field values to constants
                    .claim("scope", getAuthenticationRequest().getScope().toArray())
                    .claim("claims", getAuthenticationRequest().getClaims() == null ? null
                            : getAuthenticationRequest().getClaims().toJSONObject())
                    .build();
            try {
                getOidcResponseContext().setAuthorizationCode(
                        dataSealer.wrap(authzCodeClaims.toJSONObject().toJSONString(), dateExp.getTime()));
                log.debug("{} Setting authz code {} as {} to response context ", getLogPrefix(),
                        authzCodeClaims.toJSONObject().toJSONString(), getOidcResponseContext().getAuthorizationCode());
            } catch (DataSealerException e) {
                log.error("{} Authorization Code generation failed {}", getLogPrefix(), e.getMessage());
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
            }
        }

    }

}
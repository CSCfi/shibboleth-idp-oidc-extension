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

import java.text.ParseException;
import java.util.Collection;
import javax.annotation.Nonnull;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Action that sets requested sub value to response context. Value may be in id token hint or in claims parameter (that
 * may be in request object also). If value is in both, claims value will be used. Multiple values for subject in claims
 * parameter will be ignored.
 */
@SuppressWarnings("rawtypes")
public class SetRequestedSubjectToResponseContext extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetRequestedSubjectToResponseContext.class);

    /** id token claims in requested claims. */
    @Nonnull
    private Collection<Entry> idTokenClaims;

    /** id token hint. */
    @Nonnull
    private JWT idTokenHint;

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        if (getOidcResponseContext().getRequestedClaims() != null) {
            idTokenClaims = getOidcResponseContext().getRequestedClaims().getIDTokenClaims();
        }
        idTokenHint = getAuthenticationRequest().getIDTokenHint();
        if (idTokenClaims == null && idTokenHint == null) {
            log.debug("{} No requested claims nor id token hint, nothing to do", getLogPrefix());
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (idTokenClaims != null && !idTokenClaims.isEmpty()) {
            for (Entry entry : idTokenClaims) {
                if (IDTokenClaimsSet.SUB_CLAIM_NAME.equals(entry.getClaimName())) {
                    log.debug("{} Setting requested sub claim value {}", getLogPrefix(), entry.getValue());
                    getOidcResponseContext().setRequestedSubject(entry.getValue());
                    return;
                }
            }
        }
        try {
            if (idTokenHint != null && idTokenHint.getJWTClaimsSet() != null) {
                log.debug("{} Setting requested sub claim value {}", getLogPrefix(),
                        idTokenHint.getJWTClaimsSet().getSubject());
                getOidcResponseContext().setRequestedSubject(idTokenHint.getJWTClaimsSet().getSubject());
            }
        } catch (ParseException e) {
            log.error("{} error parsing id token hint", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
    }
}
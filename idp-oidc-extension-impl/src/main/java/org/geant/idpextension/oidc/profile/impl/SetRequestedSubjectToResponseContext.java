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
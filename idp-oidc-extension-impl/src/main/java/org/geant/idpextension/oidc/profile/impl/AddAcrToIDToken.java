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
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Action that adds acr claim to a {@link IDTokenClaimsSet}.
 * 
 * OPTIONAL. Authentication Context Class Reference. String specifying an
 * Authentication Context Class Reference value that identifies the
 * Authentication Context Class that the authentication performed satisfied. The
 * value "0" indicates the End-User authentication did not meet the requirements
 * of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived
 * browser cookie, for instance, is one example where the use of "level 0" is
 * appropriate. Authentications with level 0 SHOULD NOT be used to authorize
 * access to any resource of any monetary value. (This corresponds to the OpenID
 * 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711
 * [RFC6711] registered name SHOULD be used as the acr value; registered names
 * MUST NOT be used with a different meaning than that which is registered.
 * Parties using this claim will need to agree upon the meanings of the values
 * used, which may be context-specific. The acr value is a case sensitive
 * string.
 * 
 *
 *
 */
@SuppressWarnings("rawtypes")
public class AddAcrToIDToken extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddAcrToIDToken.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        if (getOidcResponseContext().getAcr() != null) {
            log.debug("{} Setting acr to id token", getLogPrefix());
            getOidcResponseContext().getIDToken().setACR(getOidcResponseContext().getAcr());
            log.debug("{} Updated token {}", getLogPrefix(), getOidcResponseContext().getIDToken().toJSONObject()
                    .toJSONString());
        }
    }
}
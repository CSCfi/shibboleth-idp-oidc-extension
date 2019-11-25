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

import javax.annotation.Nonnull;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Action that adds access token hash claim to a {@link IDTokenClaimsSet}. If there are no signing parameters available,
 * action fails without error event.
 */
@SuppressWarnings("rawtypes")
public class AddAccessTokenHashToIDToken extends AbstractOIDCSigningResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddAccessTokenHashToIDToken.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        if (getOidcResponseContext().getAccessToken() == null) {
            log.error("{} No access token to calculate hash on", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        AccessTokenHash atHash = AccessTokenHash.compute(getOidcResponseContext().getAccessToken(),
                new JWSAlgorithm(signatureSigningParameters.getSignatureAlgorithm()));
        if (atHash == null || atHash.getValue() == null) {
            log.error("{} Not able to generate at_hash using algorithm {}", getLogPrefix(),
                    signatureSigningParameters.getSignatureAlgorithm());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
            return;
        }
        log.debug("{} Setting access token hash to id token", getLogPrefix());
        getOidcResponseContext().getIDToken().setClaim(IDTokenClaimsSet.AT_HASH_CLAIM_NAME, atHash.getValue());
        log.debug("{} Updated token {}", getLogPrefix(),
                getOidcResponseContext().getIDToken().toJSONObject().toJSONString());

    }

}
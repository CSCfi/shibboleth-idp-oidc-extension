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
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;

/**
 * Action that forms outbound message based on response context. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 * 
 * Actions assumes {@link OidcResponseContext#getProcessedToken()} returns signed, signed and encrypted or encrypted
 * response content if such is meant to be sent to the client. Otherwise actions assumes response content is located by
 * {@link OidcResponseContext#getUserInfo()}
 */
public class FormOutboundUserInfoResponseMessage extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundUserInfoResponseMessage.class);

    /** {@inheritDoc} */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        UserInfoSuccessResponse resp;
        if (getOidcResponseContext().getProcessedToken() != null) {
            resp = new UserInfoSuccessResponse(getOidcResponseContext().getProcessedToken());
        } else if (getOidcResponseContext().getUserInfo() != null) {
            resp = new UserInfoSuccessResponse(getOidcResponseContext().getUserInfo());
        } else {
            log.error("{} no content to form userinfo response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        profileRequestContext.getOutboundMessageContext().setMessage(resp);

    }
}
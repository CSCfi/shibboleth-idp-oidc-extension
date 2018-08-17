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

import org.geant.idpextension.oidc.profile.context.navigate.DefaultUserInfoSigningAlgLookupFunction;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that forms outbound message based on user info request and response context. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 * 
 * Depending on registered metadata, the message is either signed jwt or claims set. Encryption is not yet supported.
 */
public class FormOutboundUserInfoResponseMessage extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundUserInfoResponseMessage.class);

    /** Strategy used to determine user info response signing algorithm. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Function<ProfileRequestContext, JWSAlgorithm> userInfoSigAlgStrategy;

    /**
     * Constructor.
     */
    public FormOutboundUserInfoResponseMessage() {
        userInfoSigAlgStrategy = new DefaultUserInfoSigningAlgLookupFunction();
    }

    /**
     * Set the strategy used to user info signing algorithm lookup strategy.
     * 
     * @param strategy lookup strategy
     */
    public void setUserInfoSigningAlgLookupStrategy(
            @SuppressWarnings("rawtypes") @Nonnull final Function<ProfileRequestContext, JWSAlgorithm> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        userInfoSigAlgStrategy =
                Constraint.isNotNull(strategy, "User Info Signing Algorithm lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        UserInfoSuccessResponse resp;
        if (userInfoSigAlgStrategy.apply(profileRequestContext) == null) {
            resp = new UserInfoSuccessResponse(getOidcResponseContext().getUserInfo());
        } else {
            resp = new UserInfoSuccessResponse(getOidcResponseContext().getProcessedToken());
        }
        ((MessageContext) getOidcResponseContext().getParent()).setMessage(resp);
    }
}
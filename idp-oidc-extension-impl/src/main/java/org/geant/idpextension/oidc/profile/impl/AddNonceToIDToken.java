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

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestNonceLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that adds nonce claim to a {@link IDTokenClaimsSet}.
 */
@SuppressWarnings("rawtypes")
public class AddNonceToIDToken extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddNonceToIDToken.class);

    /** Strategy used to obtain the request nonce. */
    @Nonnull
    private Function<ProfileRequestContext, Nonce> requestNonceLookupStrategy;

    /**
     * Constructor.
     */
    public AddNonceToIDToken() {
        requestNonceLookupStrategy = new DefaultRequestNonceLookupFunction();
    }

    /**
     * Set the strategy used to locate the nonce of authentication request.
     * 
     * @param strategy lookup strategy
     */
    public void setRequestNonceLookupStrategy(@Nonnull final Function<ProfileRequestContext, Nonce> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        requestNonceLookupStrategy =
                Constraint.isNotNull(strategy, "RequestNonceLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (getOidcResponseContext().getIDToken() == null) {
            log.error("{} No id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        }
        Nonce nonce = requestNonceLookupStrategy.apply(profileRequestContext);
        if (nonce != null) {
            log.debug("{} Setting nonce to id token", getLogPrefix());
            getOidcResponseContext().getIDToken().setNonce(nonce);
            log.debug("{} Updated token {}", getLogPrefix(),
                    getOidcResponseContext().getIDToken().toJSONObject().toJSONString());
        }

    }

}
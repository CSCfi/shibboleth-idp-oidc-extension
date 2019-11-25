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
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Abstract class for actions performing actions on {@link OIDCMetadataContext} located under
 * {@link ProfileRequestContext#getInboundMessageContext() . Extends base classes that offer actions on
 * {@link UserInfoRequest} found via {@link ProfileRequestContext#getInboundMessageContext()#getMessage()} and on
 * {@link OIDCAuthenticationResponseContext} located under {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
@SuppressWarnings("rawtypes")
abstract class AbstractOIDCUserInfoResponseAction extends AbstractOIDCUserInfoValidationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AbstractOIDCUserInfoResponseAction.class);

    /** OIDC Metadata context. */
    @Nonnull
    private OIDCMetadataContext oidcMetadataContext;

    /**
     * Returns the OIDC Metadata context.
     * 
     * @return The OIDC Metadata context.
     */
    public OIDCMetadataContext getMetadataContext() {
        return oidcMetadataContext;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        oidcMetadataContext =
                profileRequestContext.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, false);
        if (oidcMetadataContext == null) {
            log.error("{} No metadata found for relying party", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

}
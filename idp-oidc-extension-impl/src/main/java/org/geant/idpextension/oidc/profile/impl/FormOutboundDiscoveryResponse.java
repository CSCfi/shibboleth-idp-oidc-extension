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
import org.geant.idpextension.oidc.messaging.JSONSuccessResponse;
import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * This action builds a response for the OP configuration discovery request. The response contains the contents of the
 * attached {@link ProviderMetadataResolver}, possibly containing dynamic values.
 */
@SuppressWarnings("rawtypes")
public class FormOutboundDiscoveryResponse extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(FormOutboundDiscoveryResponse.class);

    /** The resolver for the metadata that is being distributed. */
    private ProviderMetadataResolver metadataResolver;

    /** metadata to publish. */
    private OIDCProviderMetadata metadata;;

    /** Constructor. */
    public FormOutboundDiscoveryResponse() {
        super();
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (metadataResolver == null) {
            throw new ComponentInitializationException("The metadata resolver cannot be null!");
        }
    }

    /**
     * Set the resolver for the metadata that is being distributed.
     * 
     * @param resolver What to set.
     */
    public void setMetadataResolver(final ProviderMetadataResolver resolver) {
        metadataResolver = Constraint.isNotNull(resolver, "The metadata resolver cannot be null!");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        try {
            metadata = metadataResolver.resolveSingle(profileRequestContext);
        } catch (ResolverException e) {
            log.error("{} Could not resolve provider metadata", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        if (metadata == null) {
            log.error("{} Could not resolve provider metadata", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        profileRequestContext.getOutboundMessageContext().setMessage(new JSONSuccessResponse(metadata.toJSONObject()));
    }
}

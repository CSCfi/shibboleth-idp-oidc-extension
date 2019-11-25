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

import java.util.Set;
import javax.annotation.Nonnull;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestResponseTypeLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.ResponseType;

/**
 * An action that validates the requested response_type is registered to the requesting RP.
 */
public class ValidateResponseType extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateResponseType.class);

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<ResponseType> registeredTypes =
                getMetadataContext().getClientInformation().getMetadata().getResponseTypes();
        final ResponseType requestedType = new DefaultRequestResponseTypeLookupFunction().apply(profileRequestContext);
        if (registeredTypes == null || registeredTypes.isEmpty() || !registeredTypes.contains(requestedType)) {
            log.warn("{} The response type {} is not registered for this RP", getLogPrefix(), requestedType);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_RESPONSE_TYPE);
        }
    }
}

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
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;

/**
 * An action that validates the grant type is registered to the requesting RP. This action is used in Token end point to
 * check if authorization code or refresh token has been registered to be used as a grant.
 */
public class ValidateGrantType extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateGrantType.class);

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<GrantType> registeredTypes =
                getMetadataContext().getClientInformation().getMetadata().getGrantTypes();
        AuthorizationGrant grant = getTokenRequest().getAuthorizationGrant();
        if (registeredTypes == null || registeredTypes.isEmpty() || !registeredTypes.contains(grant.getType())) {
            log.error("{} The grant type {} is not registered for this RP", getLogPrefix(), grant.getType().getValue());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_GRANT_TYPE);
        }
    }
}

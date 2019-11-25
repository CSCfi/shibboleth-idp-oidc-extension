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

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.rp.ApplicationType;

/**
 * <p>Adds the application_type to the {@link OIDCClientRegistrationResponseContext}. The default, it the value does
 * not exists from the request, is web (as defined in the specification).</p>
 */
@SuppressWarnings("rawtypes")
public class AddApplicationTypeToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddApplicationTypeToClientMetadata.class);
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final ApplicationType requestType = getInputMetadata().getApplicationType();
        if (requestType == null) {
            log.debug("{} application_type was not defined, defining it as {}", getLogPrefix(), 
                    ApplicationType.getDefault());
            getOutputMetadata().setApplicationType(ApplicationType.getDefault());
        } else {
            getOutputMetadata().setApplicationType(requestType);
            log.debug("{} application_type set as {}", getLogPrefix(), requestType);
        }
    }

}
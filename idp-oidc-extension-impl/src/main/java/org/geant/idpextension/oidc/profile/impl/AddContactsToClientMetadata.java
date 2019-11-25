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

import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adds the contents of the contacts attribute from the input metadata to the output {@link OIDCClientMetadata}.
 */
public class AddContactsToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddContactsToClientMetadata.class);
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final List<String> contacts = getInputMetadata().getEmailContacts();
        if (contacts != null && !contacts.isEmpty()) {
            log.debug("{} contacts will be populated as {}", getLogPrefix(), contacts);
            getOutputMetadata().setEmailContacts(contacts);
        } else {
            log.debug("{} no contacts were defined in the input metadata", getLogPrefix());
        }
    }

}

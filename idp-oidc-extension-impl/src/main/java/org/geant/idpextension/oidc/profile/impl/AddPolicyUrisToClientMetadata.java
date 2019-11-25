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

import java.net.URI;
import java.util.Map;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.langtag.LangTag;

/**
 * This action adds the policy_uri(s) to the client metadata.
 */
public class AddPolicyUrisToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddPolicyUrisToClientMetadata.class);
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Map<LangTag,URI> uris = getInputMetadata().getPolicyURIEntries();
        if (uris == null) {
            log.debug("{} No policy uris defined in the request", getLogPrefix());
            return;
        }
        for (final LangTag tag : uris.keySet()) {
            log.debug("{} Added a policy URI {} for language {}", getLogPrefix(), uris.get(tag), tag);
            getOutputMetadata().setPolicyURI(uris.get(tag), tag);
        }
    }
}

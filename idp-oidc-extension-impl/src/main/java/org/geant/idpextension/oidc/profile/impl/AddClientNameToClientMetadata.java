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

import java.util.Iterator;
import java.util.Map;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.langtag.LangTag;

import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Adds client name from the input metadata to the output {@link OIDCClientMetadata}. The name with and without
 * language tag(s) are populated from the input.
 */
public class AddClientNameToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddClientNameToClientMetadata.class);
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final String nameNoTag = StringSupport.trimOrNull(getInputMetadata().getName());
        final Map<LangTag, String> map = getInputMetadata().getNameEntries();
        if (nameNoTag != null) {
            log.debug("{} Found client name without name tag: {}", getLogPrefix(), nameNoTag);
            getOutputMetadata().setName(nameNoTag, null);
        }
        if (map != null && !map.isEmpty()) {
            final Iterator<LangTag> tags = map.keySet().iterator();
            while (tags.hasNext()) {
                final LangTag tag = tags.next();
                final String name = StringSupport.trimOrNull(map.get(tag));
                if (name != null) {
                    log.debug("{} Found client name {} for language tag {}", getLogPrefix(), name, tag);
                    getOutputMetadata().setName(name, tag);
                }
            }
        }
    }

}

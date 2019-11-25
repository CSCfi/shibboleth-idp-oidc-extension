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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A function that returns responder id based on profile. */
@SuppressWarnings("rawtypes")
public class ProfileResponderIdLookupFunction extends AbstractIdentifiableInitializableComponent
        implements ContextDataLookupFunction<ProfileRequestContext, String> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ProfileResponderIdLookupFunction.class);

    /** Default responder value, usually entity id. */
    @Nonnull
    private String defaultResponder;

    /** Mapping from profile id to responder value. */
    @Nonnull
    private Map<String, String> profileResponders = new HashMap<String, String>();

    /**
     * Set default responder value, usually entity id.
     * 
     * @param resp default responder value, usually entity id
     */
    public void setDefaultResponder(@Nonnull String resp) {
        defaultResponder = Constraint.isNotNull(resp, "Default responder cannot be null");
    }

    /**
     * Set mapping from profile to responder value.
     * 
     * @param resp mapping from profile to responder value
     */
    public void setProfileResponders(@Nullable Map<ProfileConfiguration, String> resp) {
        profileResponders.clear();
        if (resp != null) {
            for (Map.Entry<ProfileConfiguration, String> entry : resp.entrySet()) {
                if (entry.getKey() != null && entry.getKey().getId() != null && entry.getValue() != null) {
                    profileResponders.put(entry.getKey().getId(), entry.getValue());
                }
            }
        }

    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (defaultResponder == null) {
            throw new ComponentInitializationException("Default responder cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public String apply(@Nullable final ProfileRequestContext input) {
        if (profileResponders.containsKey(input.getProfileId())) {
            return profileResponders.get(input.getProfileId());
        }
        return defaultResponder;
    }

}
/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
public class ProfileResponderIdLookupFunction extends AbstractIdentifiableInitializableComponent implements
        ContextDataLookupFunction<ProfileRequestContext, String> {

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
     * @param resp
     *            default responder value, usually entity id
     */
    public void setDefaultResponder(@Nonnull String resp) {
        defaultResponder = Constraint.isNotNull(resp, "Default responder cannot be null");
    }

    /**
     * Set mapping from profile to responder value.
     * 
     * @param resp
     *            mapping from profile to responder value
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
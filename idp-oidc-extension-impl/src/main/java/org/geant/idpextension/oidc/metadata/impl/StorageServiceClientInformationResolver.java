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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.opensaml.storage.StorageRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A {@link ClientInformationResolver} exploiting {@link StorageService} for fetching the stored data.
 */
public class StorageServiceClientInformationResolver extends BaseStorageServiceClientInformationComponent 
    implements ClientInformationResolver {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(StorageServiceClientInformationResolver.class);
    
    /** Constructor. */
    public StorageServiceClientInformationResolver() {
        super();
    }
    
    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCClientInformation> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final ClientIDCriterion clientIdCriterion = criteria.get(ClientIDCriterion.class);
        if (clientIdCriterion == null || clientIdCriterion.getClientID() == null) {
            log.warn("No client ID criteria found, returning empty set.");
            return Collections.emptyList();
        }
        //TODO: support other criterion
        final String clientId = clientIdCriterion.getClientID().getValue();
        final List<OIDCClientInformation> result = new ArrayList<>();
        try {
            final StorageRecord record = getStorageService().read(CONTEXT_NAME, clientId);
            if (record == null) {
                log.error("Could not find any records with clientId {}", clientId);
            } else {
                final OIDCClientInformation clientInformation = 
                        OIDCClientInformation.parse(JSONObjectUtils.parse(record.getValue()));
                log.debug("Found a record with clientId {}", clientId);
                result.add(clientInformation);
            }
        } catch (IOException | ParseException e) {
            log.error("Could not read the storage data", e);
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public OIDCClientInformation resolveSingle(CriteriaSet criteria) throws ResolverException {
        final Iterable<OIDCClientInformation> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<OIDCClientInformation> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        log.warn("Could not find any clients with the given criteria");
        return null;
    }
}

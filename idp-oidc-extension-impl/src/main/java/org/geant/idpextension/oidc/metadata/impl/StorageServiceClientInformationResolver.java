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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RemoteJwkSetCache;
import org.opensaml.storage.StorageRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A {@link ClientInformationResolver} exploiting {@link StorageService} for fetching the stored data.
 */
public class StorageServiceClientInformationResolver extends BaseStorageServiceClientInformationComponent
        implements ClientInformationResolver {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(StorageServiceClientInformationResolver.class);

    /** The cache for remote JWK key sets. */
    private RemoteJwkSetCache remoteJwkSetCache;

    /** The remote key refresh interval in milliseconds. Default value: 1800000ms */
    @Duration
    @Positive
    private long keyFetchInterval = 1800000;

    /** Constructor. */
    public StorageServiceClientInformationResolver() {
        super();
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (remoteJwkSetCache == null) {
            log.warn("The RemoteJwkSetCache is not defined, the remote keys are not fetched automatically");
        }
    }

    /**
     * Set the cache for remote JWK key sets.
     * 
     * @param jwkSetCache What to set.
     */
    public void setRemoteJwkSetCache(final RemoteJwkSetCache jwkSetCache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        remoteJwkSetCache = Constraint.isNotNull(jwkSetCache, "The remote JWK set cache cannot be null");
    }

    /**
     * Set the remote key refresh interval (in milliseconds).
     * 
     * @param interval What to set.
     */
    public void setKeyFetchInterval(@Duration @Positive long interval) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (interval < 0) {
            throw new IllegalArgumentException("Remote key refresh must be greater than 0");
        }
        keyFetchInterval = interval;
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
        // TODO: support other criterion
        final String clientId = clientIdCriterion.getClientID().getValue();
        final List<OIDCClientInformation> result = new ArrayList<>();
        try {
            final StorageRecord record = getStorageService().read(CONTEXT_NAME, clientId);
            if (record == null) {
                log.debug("Could not find any records with clientId {}", clientId);
            } else {
                final OIDCClientInformation clientInformation =
                        OIDCClientInformation.parse(JSONObjectUtils.parse(record.getValue()));
                log.debug("Found a record with clientId {}", clientId);
                if (clientInformation.getOIDCMetadata().getJWKSetURI() != null && remoteJwkSetCache != null) {
                    clientInformation.getOIDCMetadata().setJWKSet(remoteJwkSetCache
                            .fetch(clientInformation.getOIDCMetadata().getJWKSetURI(), 
                                    System.currentTimeMillis() + keyFetchInterval));
                }
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

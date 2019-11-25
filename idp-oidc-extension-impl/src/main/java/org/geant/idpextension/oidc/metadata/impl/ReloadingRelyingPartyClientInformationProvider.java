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

import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * This class uses the service interface to implement {@link ClientInformationResolver}.
 * Based on net.shibboleth.idp.saml.metadata.impl.ReloadingRelyingPartyMetadataProvider.
 */
public class ReloadingRelyingPartyClientInformationProvider extends AbstractIdentifiableInitializableComponent 
    implements ClientInformationResolver {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ReloadingRelyingPartyClientInformationProvider.class);

    /** The service which managed the reloading. */
    private final ReloadableService<ClientInformationResolver> service;

    /**
     * Constructor.
     * 
     * @param resolverService the service which will manage the loading.
     */
    public ReloadingRelyingPartyClientInformationProvider(
            @Nonnull final ReloadableService<ClientInformationResolver> resolverService) {
        service = Constraint.isNotNull(resolverService, "ClientInformationResolver Service cannot be null");
    }

    /** {@inheritDoc} */
    @Override @Nonnull public Iterable<OIDCClientInformation> resolve(final CriteriaSet criteria) 
            throws ResolverException {

        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ServiceableComponent<ClientInformationResolver> component = null;
        try {
            component = service.getServiceableComponent();
            if (null == component) {
                log.error("RelyingPartyClientInformationProvider '{}': Error accessing underlying source: "
                        + "Invalid configuration.", getId());
            } else {
                final ClientInformationResolver resolver = component.getComponent();
                return resolver.resolve(criteria);
            }
        } catch (final ResolverException e) {
            log.error("RelyingPartyClientInformationProvider '{}': Error during resolution", getId(), e);
        } finally {
            if (null != component) {
                component.unpinComponent();
            }
        }
        return Collections.emptySet();
    }

    /** {@inheritDoc} */
    @Override @Nullable public OIDCClientInformation resolveSingle(final CriteriaSet criteria) 
            throws ResolverException {

        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ServiceableComponent<ClientInformationResolver> component = null;
        try {
            component = service.getServiceableComponent();
            if (null == component) {
                log.error("RelyingPartyClientInformationProvider '{}': Error accessing underlying source: "
                        + "Invalid configuration.", getId());
            } else {
                final ClientInformationResolver resolver = component.getComponent();
                return resolver.resolveSingle(criteria);
            }
        } catch (final ResolverException e) {
            log.error("RelyingPartyResolver '{}': Error during resolution", getId(), e);
        } finally {
            if (null != component) {
                component.unpinComponent();
            }
        }
        return null;
    }
}

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

import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.client.ClientInformation;

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
    @Override @Nonnull public Iterable<ClientInformation> resolve(final CriteriaSet criteria) throws ResolverException {

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
        return Collections.EMPTY_SET;
    }

    /** {@inheritDoc} */
    @Override @Nullable public ClientInformation resolveSingle(final CriteriaSet criteria) throws ResolverException {

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

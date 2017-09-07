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

package org.geant.idpextension.oidc.profile.spring.relyingparty.metadata.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.impl.ChainingClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RelyingPartyClientInformationProvider;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.ApplicationContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.service.ServiceException;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * Strategy for summoning up a {@link ClientInformationResolver} from a populated {@link ApplicationContext}. <br/>
 * The logic is the same as in 
 * net.shibboleth.idp.profile.spring.relyingparty.metadata.impl.MetadataResolverServiceStrategy.
 */
public class ClientInformationResolverServiceStrategy extends AbstractIdentifiableInitializableComponent
        implements Function<ApplicationContext, ServiceableComponent<ClientInformationResolver>> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public ServiceableComponent<ClientInformationResolver> apply(@Nullable final ApplicationContext appContext) {
        final Collection<RelyingPartyClientInformationProvider> resolvers =
                appContext.getBeansOfType(RelyingPartyClientInformationProvider.class).values();

        if (resolvers.isEmpty()) {
            throw new ServiceException(
                    "Reload did not produce any bean of type" + RelyingPartyClientInformationProvider.class.getName());
        }
        if (1 == resolvers.size()) {
            // done
            return resolvers.iterator().next();
        }
        // initialize so we can sort
        for (final RelyingPartyClientInformationProvider resolver : resolvers) {
            try {
                resolver.initialize();
            } catch (final ComponentInitializationException e) {
                throw new BeanCreationException("could not preinitialize , client information provider " 
                        + resolver.getId(), e);
            }
        }

        final List<RelyingPartyClientInformationProvider> resolverList = new ArrayList<>(resolvers.size());
        resolverList.addAll(resolvers);
        Collections.sort(resolverList);
        final ChainingClientInformationResolver chain = new ChainingClientInformationResolver();
        try {
            chain.setResolvers(resolverList);
            chain.setId("MultiFileResolverFor:" + resolvers.size() + ":Resources");
            chain.initialize();
            final RelyingPartyClientInformationProvider result = new RelyingPartyClientInformationProvider();
            result.setEmbeddedResolver(chain);
            result.initialize();
            return result;
        } catch (final ResolverException | ComponentInitializationException e) {
            throw new ServiceException("Chaining constructor create failed", e);
        }
    }
}

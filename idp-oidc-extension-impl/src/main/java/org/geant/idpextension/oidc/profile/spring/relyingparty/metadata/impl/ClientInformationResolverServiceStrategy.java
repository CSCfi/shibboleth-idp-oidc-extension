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

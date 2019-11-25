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

import java.util.Collection;

import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.ServiceableProviderMetadataProvider;
import org.springframework.context.ApplicationContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.service.ServiceException;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * Strategy for summoning up a {@link ProviderMetadataResolver} from a populated {@link ApplicationContext}. <br/>
 * The logic is the same as in 
 * net.shibboleth.idp.profile.spring.relyingparty.metadata.impl.MetadataResolverServiceStrategy.
 */
public class ProviderMetadataResolverServiceStrategy extends AbstractIdentifiableInitializableComponent
        implements Function<ApplicationContext, ServiceableComponent<ProviderMetadataResolver>> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public ServiceableComponent<ProviderMetadataResolver> apply(@Nullable final ApplicationContext appContext) {
        final Collection<ServiceableProviderMetadataProvider> resolvers =
                appContext.getBeansOfType(ServiceableProviderMetadataProvider.class).values();

        if (resolvers.isEmpty()) {
            throw new ServiceException(
                    "Reload did not produce any bean of type" + ServiceableProviderMetadataProvider.class.getName());
        }
        if (1 == resolvers.size()) {
            // done
            return resolvers.iterator().next();
        }

        throw new ServiceException(
                "Reload did produce more than one bean of type" + ServiceableProviderMetadataProvider.class.getName());

    }
}

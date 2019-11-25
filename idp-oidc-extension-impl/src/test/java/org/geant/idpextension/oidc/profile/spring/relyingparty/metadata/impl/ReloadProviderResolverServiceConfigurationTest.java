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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.geant.idpextension.oidc.metadata.impl.FilesystemProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableProviderMetadataResolver;
import org.geant.idpextension.oidc.metadata.resolver.ServiceableProviderMetadataProvider;
import org.joda.time.DateTime;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.ext.spring.service.ReloadableSpringService;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.impl.ReloadServiceConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.service.ServiceException;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * Unit tests for {@link ProviderMetadataResolverServiceStrategy}.
 * 
 * Mostly based on <pre>net.shibboleth.idp.profile.spring.relyingparty.metadata.ReloadServiceConfigurationTest</pre>.
 */
public class ReloadProviderResolverServiceConfigurationTest {

    /** The service. */
    private ReloadableSpringService<RefreshableProviderMetadataResolver> service;

    private RequestContext src;
    
    private List<Resource> oneResolver;
    
    @BeforeClass public void setup() throws IOException, ComponentInitializationException {
        service = new ReloadableSpringService(ProviderMetadataResolver.class, new ProviderMetadataResolverServiceStrategy());
        service.setFailFast(true);
        service.setId("mockId");
        
        oneResolver = new ArrayList<>();
        oneResolver.add(new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/oidc-metadata-providers.xml"));
        
        service.setServiceConfigurations(oneResolver);
    }
    
    @BeforeMethod public void setUpAction() throws ComponentInitializationException {
        src = new RequestContextBuilder().buildRequestContext();
    }

    @Test public void oneResource() {
        final DateTime time = service.getLastReloadAttemptInstant();
        service.setServiceConfigurations(oneResolver);
        service.reload();
        Assert.assertNotEquals(time, service.getLastReloadAttemptInstant());
        final ServiceableComponent<RefreshableProviderMetadataResolver> component = service.getServiceableComponent();
        final ProviderMetadataResolver resolver = component.getComponent();
        component.unpinComponent();
        Assert.assertTrue(resolver instanceof ServiceableProviderMetadataProvider);
        final ServiceableProviderMetadataProvider rpProvider = (ServiceableProviderMetadataProvider) resolver;
        final ProviderMetadataResolver embedded = rpProvider.getEmbeddedResolver();
        Assert.assertTrue(embedded instanceof FilesystemProviderMetadataResolver);
    }
    
    @Test(expectedExceptions = ServiceException.class) public void noResources() 
            throws ComponentInitializationException {
        service.setServiceConfigurations(new ArrayList<Resource>());
        service.reload();
    }

    @Test public void serviceAction() throws ComponentInitializationException {
        final DateTime time = service.getLastReloadAttemptInstant();

        final MockHttpServletResponse response = new MockHttpServletResponse();
        
        final ReloadServiceConfiguration action =
                ReloadClientResolverServiceConfigurationTest.initializeAction(service, response);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);

        Assert.assertNotEquals(time, service.getLastReloadAttemptInstant());
        Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
    }
    
    @AfterClass public void teardown() {
        ComponentSupport.destroy(service);
    }

}
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.geant.idpextension.oidc.metadata.impl.ChainingClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RelyingPartyClientInformationProvider;
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

import com.google.common.base.Function;

import net.shibboleth.ext.spring.service.ReloadableSpringService;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.impl.ReloadServiceConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceException;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * Unit tests for {@link ClientInformationResolverServiceStrategy}.
 * 
 * Mostly based on <pre>net.shibboleth.idp.profile.spring.relyingparty.metadata.ReloadServiceConfigurationTest</pre>.
 */
public class ReloadClientResolverServiceConfigurationTest {

    /** The service. */
    private ReloadableSpringService<RefreshableClientInformationResolver> service;

    private RequestContext src;
    
    private List<Resource> oneResolver;
    
    private List<Resource> twoResolvers;
    
    @BeforeClass public void setup() throws IOException, ComponentInitializationException {
        service = new ReloadableSpringService(ClientInformationResolver.class, new ClientInformationResolverServiceStrategy());
        service.setFailFast(true);
        service.setId("mockId");
        
        oneResolver = new ArrayList<>();
        oneResolver.add(new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/oidc-metadata-providers.xml"));
        
        twoResolvers = new ArrayList<>();
        twoResolvers.add(new ClassPathResource("/org/geant/idpextension/oidc/metadata/impl/oidc-metadata-providers2.xml"));

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
        final ServiceableComponent<RefreshableClientInformationResolver> component = service.getServiceableComponent();
        final ClientInformationResolver resolver = component.getComponent();
        component.unpinComponent();
        Assert.assertEquals(getChainSize(resolver), 1);
    }
    
    protected int getChainSize(final ClientInformationResolver resolver) {
        Assert.assertTrue(resolver instanceof RelyingPartyClientInformationProvider);
        final RelyingPartyClientInformationProvider rpProvider = (RelyingPartyClientInformationProvider) resolver;
        final ClientInformationResolver embedded = rpProvider.getEmbeddedResolver();
        Assert.assertTrue(embedded instanceof ChainingClientInformationResolver);
        final ChainingClientInformationResolver chain = (ChainingClientInformationResolver) embedded;
        return chain.getResolvers().size();
    }

    @Test public void twoResources() {
        final DateTime time = service.getLastReloadAttemptInstant();
        service.setServiceConfigurations(twoResolvers);
        service.reload();
        Assert.assertNotEquals(time, service.getLastReloadAttemptInstant());
        final ServiceableComponent<RefreshableClientInformationResolver> component = service.getServiceableComponent();
        final ClientInformationResolver resolver = component.getComponent();
        component.unpinComponent();
        Assert.assertEquals(getChainSize(resolver), 2);
    }

    @Test(expectedExceptions = ServiceException.class) public void noResources() 
            throws ComponentInitializationException {
        service.setServiceConfigurations(new ArrayList<Resource>());
        service.reload();
    }

    @Test public void serviceAction() throws ComponentInitializationException {
        final DateTime time = service.getLastReloadAttemptInstant();

        final MockHttpServletResponse response = new MockHttpServletResponse();
        
        final ReloadServiceConfiguration action = initializeAction(service, response);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);

        Assert.assertNotEquals(time, service.getLastReloadAttemptInstant());
        Assert.assertEquals(response.getStatus(), HttpServletResponse.SC_OK);
    }
    
    protected static ReloadServiceConfiguration initializeAction(final ReloadableService reloadableService, 
            final HttpServletResponse response) throws ComponentInitializationException {
        final ReloadServiceConfiguration action = new ReloadServiceConfiguration();
        action.setHttpServletResponse(response);
        action.setServiceLookupStrategy(new Function<ProfileRequestContext,ReloadableService>() {
            public ReloadableService apply(ProfileRequestContext input) {
                return reloadableService;
            }
        });
        action.initialize();
        return action;
    }
    
    @AfterClass public void teardown() {
        ComponentSupport.destroy(service);
    }

}
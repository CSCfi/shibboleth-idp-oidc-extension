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

package org.geant.idpextension.oidc.metadata.resolver;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.joda.time.DateTime;
import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Unit tests for {@link ServiceableProviderMetadataProvider}.
 */
public class ServiceableProviderMetadataProviderTest {
    
    ServiceableProviderMetadataProvider provider;
    DateTime lastRefresh;
    DateTime lastUpdate;
    
    @BeforeMethod
    public void setup() {
        provider = new ServiceableProviderMetadataProvider();
        lastRefresh = new DateTime();
        lastUpdate = new DateTime().minusHours(1);
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoId() throws ComponentInitializationException {
        provider.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoResolver() throws ComponentInitializationException {
        provider.setId("mockId");
        provider.initialize();
    }
    
    @Test
    public void testEquals() throws ResolverException, URISyntaxException, ComponentInitializationException {
        int sortKey = 1234;
        provider.setId("mockId");
        provider.setEmbeddedResolver(buildMetadataResolver("mock1", "mock2"));
        provider.setSortKey(sortKey);
        provider.initialize();
        
        ServiceableProviderMetadataProvider provider2 = new ServiceableProviderMetadataProvider();
        provider2.setId("mockId");
        provider2.setEmbeddedResolver(buildMetadataResolver("mock1", "mock2"));
        provider2.setSortKey(sortKey);
        provider2.initialize();

        ServiceableProviderMetadataProvider provider3 = new ServiceableProviderMetadataProvider();
        provider3.setId("mockId");
        provider3.setEmbeddedResolver(buildMetadataResolver("mock1", "mock2"));
        provider3.setSortKey(sortKey + 1);
        provider3.initialize();

        Assert.assertTrue(provider.equals(provider2));
        Assert.assertFalse(provider.equals(provider3));
    }

    @Test
    public void testResolver() throws ComponentInitializationException, ResolverException, URISyntaxException {
        provider.setId("mockId");
        provider.setEmbeddedResolver(buildMetadataResolver("mock1", "mock2"));
        provider.initialize();
        Iterable<OIDCProviderMetadata> iterable = provider.resolve(null);
        Iterator<OIDCProviderMetadata> iterator = iterable.iterator();
        OIDCProviderMetadata metadata = iterator.next();
        Assert.assertTrue(metadata.getIssuer().getValue().equals("mock1") 
                || metadata.getIssuer().getValue().equals("mock2"));
        metadata = iterator.next();
        Assert.assertTrue(metadata.getIssuer().getValue().equals("mock1") 
                || metadata.getIssuer().getValue().equals("mock2"));
        Assert.assertFalse(iterator.hasNext());
        Assert.assertEquals("mock1", provider.resolveSingle(null).getIssuer().getValue());
    }
    
    @Test
    public void testLastUpdateAndRefresh() throws ResolverException, URISyntaxException,
            ComponentInitializationException {
        provider.setId("mockId");
        provider.setEmbeddedResolver(buildMetadataResolver("mock1", "mock2"));
        provider.initialize();
        Assert.assertEquals(lastUpdate, provider.getLastUpdate());
        Assert.assertEquals(lastRefresh, provider.getLastRefresh());
    }
    
    protected ProviderMetadataResolver buildMetadataResolver(String...names) throws ResolverException,
            URISyntaxException {
        RefreshableProviderMetadataResolver resolver = Mockito.mock(RefreshableProviderMetadataResolver.class);
        Mockito.when(resolver.resolve((ProfileRequestContext) Mockito.any())).thenReturn(createMetadataList(names));
        Mockito.when(resolver.resolveSingle((ProfileRequestContext) Mockito.any())).
            thenReturn(createMetadata(names[0]));
        Mockito.when(resolver.getLastRefresh()).thenReturn(lastRefresh);
        Mockito.when(resolver.getLastUpdate()).thenReturn(lastUpdate);
        return resolver;
    }

    protected ProviderMetadataResolver buildMetadataResolver(boolean refreshable, String...names)
            throws ResolverException, URISyntaxException {
        RefreshableProviderMetadataResolver resolver = Mockito.mock(RefreshableProviderMetadataResolver.class);
        Mockito.when(resolver.resolve((ProfileRequestContext) Mockito.any())).thenReturn(createMetadataList(names));
        Mockito.when(resolver.resolveSingle((ProfileRequestContext) Mockito.any())).
            thenReturn(createMetadata(names[0]));
        Mockito.when(resolver.getLastRefresh()).thenReturn(lastRefresh);
        Mockito.when(resolver.getLastUpdate()).thenReturn(lastUpdate);
        return resolver;
    }
    
    
    protected List<OIDCProviderMetadata> createMetadataList(String... names) throws URISyntaxException {
        List<OIDCProviderMetadata> list = new ArrayList<>();
        for (String name : names) {
            list.add(createMetadata(name));
        }
        return list;
    }
    
    protected OIDCProviderMetadata createMetadata(String name) throws URISyntaxException {
        Issuer issuer = new Issuer(name);
        return new OIDCProviderMetadata(issuer, Arrays.asList(SubjectType.PUBLIC), new URI("http://example.org"));
    }
}

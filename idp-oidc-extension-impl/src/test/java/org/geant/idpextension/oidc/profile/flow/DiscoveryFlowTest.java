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

package org.geant.idpextension.oidc.profile.flow;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Unit test for the OP discovery flow.
 */
public class DiscoveryFlowTest extends AbstractOidcFlowTest {
    
    public static final String FLOW_ID = "oidc/discovery";

    protected DiscoveryFlowTest() {
        super(FLOW_ID);
    }
    
    @Test
    public void test() throws ParseException, IOException {
        final FlowExecutionResult result = flowExecutor.launchExecution(FLOW_ID, null, externalContext);
        final Response response = parseResponse(result);
        Assert.assertTrue(response.indicatesSuccess());
        final Resource resource = new FileSystemResource("src/test/resources/conf/openid-configuration.json");
        final OIDCProviderMetadata originalMetadata = 
                OIDCProviderMetadata.parse(IOUtils.toString(resource.getInputStream(), "UTF-8"));
        Assert.assertNotNull(originalMetadata.getIDTokenJWSAlgs());
        Assert.assertTrue(containsAll(originalMetadata.getIDTokenJWSAlgs(), Arrays.asList("RS256")));
        Assert.assertNull(originalMetadata.getIDTokenJWEAlgs());
        Assert.assertNull(originalMetadata.getIDTokenJWEEncs());
        Assert.assertNull(originalMetadata.getUserInfoJWEAlgs());
        Assert.assertNull(originalMetadata.getUserInfoJWEEncs());
        Assert.assertNull(originalMetadata.getUserInfoJWSAlgs());
        final OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(response.toHTTPResponse().getContent());
        Assert.assertEquals(metadata.getIssuer(), new Issuer("https://op.example.org"));;
        final List<String> jweAlgs = Arrays.asList("RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW",
                "A128GCMKW", "A192GCMKW", "A256GCMKW");
        final List<String> jweEncs = Arrays.asList("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", 
                "A192GCM", "A256GCM");
        final List<String> jwsAlgs = Arrays.asList("RS256", "RS384", "RS512", "ES256", "HS256", "HS384", "HS512");
        Assert.assertNotNull(metadata.getIDTokenJWEAlgs());
        Assert.assertTrue(containsAll(metadata.getIDTokenJWEAlgs(), jweAlgs));
        Assert.assertNotNull(metadata.getIDTokenJWEAlgs());
        Assert.assertTrue(containsAll(metadata.getIDTokenJWEEncs(), jweEncs));
        Assert.assertNotNull(metadata.getIDTokenJWEEncs());
        Assert.assertTrue(containsAll(metadata.getIDTokenJWSAlgs(), jwsAlgs));
        Assert.assertNotNull(metadata.getUserInfoJWEAlgs());
        Assert.assertTrue(containsAll(metadata.getUserInfoJWEAlgs(), jweAlgs));
        Assert.assertNotNull(metadata.getUserInfoJWEAlgs());
        Assert.assertTrue(containsAll(metadata.getUserInfoJWEEncs(), jweEncs));
        Assert.assertNotNull(metadata.getUserInfoJWEEncs());
        Assert.assertTrue(containsAll(metadata.getUserInfoJWSAlgs(), jwsAlgs));
    }
    
    protected boolean containsAll(Collection<? extends Algorithm> algs, Collection<String> strings) {
        final List<String> algStrings = new ArrayList<>();
        for (final Algorithm alg : algs) {
            algStrings.add(alg.toString());
        }
        return strings.size() == algStrings.size() ? strings.containsAll(strings) : false;
    }

}

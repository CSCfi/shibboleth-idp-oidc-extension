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

package org.geant.idpextension.oidc.attribute.filter.spring.policyrule.filtercontext.impl;

import net.shibboleth.idp.attribute.filter.PolicyRequirementRule.Tristate;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;

public class AttributeOIDCScopePolicyRuleTest {

    private AttributeOIDCScopePolicyRule rule;
    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;
    private AttributeFilterContext filtercontext;
    private OIDCAuthenticationResponseContext authRespCtx;
    private MessageContext<AuthenticationResponse> msgCtx;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    private void setUp() throws Exception {
        rule = new AttributeOIDCScopePolicyRule();
        rule.setMatchString("test");
        rule.setId("componentId");
        rule.initialize();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        msgCtx = new MessageContext<AuthenticationResponse>();
        prc.setOutboundMessageContext(msgCtx);
        // shortcut, may break the test
        filtercontext = prc.getSubcontext(AttributeFilterContext.class, true);
        authRespCtx = new OIDCAuthenticationResponseContext();
        msgCtx.addSubcontext(authRespCtx);
        Scope scope = new Scope();
        scope.add("openid");
        scope.add("test");
        authRespCtx.setScope(scope);
    }

    @Test
    public void testMatch() throws Exception {
        Assert.assertEquals(Tristate.TRUE, rule.matches(filtercontext));
    }

    @Test
    public void testNoMatch() throws Exception {
        Scope scope = new Scope();
        scope.add("openid");
        scope.add("test_no_match");
        authRespCtx.setScope(scope);
        Assert.assertEquals(Tristate.FALSE, rule.matches(filtercontext));
    }

    @Test
    public void testNoOIDCRespCtx() throws Exception {
        msgCtx.removeSubcontext(OIDCAuthenticationResponseContext.class);
        Assert.assertEquals(Tristate.FALSE, rule.matches(filtercontext));
    }

    @Test
    public void testNoScope() throws Exception {
        Scope scope = new Scope();
        authRespCtx.setScope(scope);
        Assert.assertEquals(Tristate.FAIL, rule.matches(filtercontext));
    }

}
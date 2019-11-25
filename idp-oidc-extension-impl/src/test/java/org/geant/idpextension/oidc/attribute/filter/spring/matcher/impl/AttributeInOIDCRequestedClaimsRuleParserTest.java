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

package org.geant.idpextension.oidc.attribute.filter.spring.matcher.impl;

import org.geant.idpextension.oidc.attribute.filter.matcher.impl.AttributeInOIDCRequestedClaimsMatcher;
import org.springframework.context.support.GenericApplicationContext;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.ext.spring.context.FilesystemGenericApplicationContext;
import net.shibboleth.idp.attribute.filter.AttributeRule;
import net.shibboleth.idp.attribute.filter.Matcher;
import net.shibboleth.idp.attribute.filter.spring.BaseAttributeFilterParserTest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class AttributeInOIDCRequestedClaimsRuleParserTest extends BaseAttributeFilterParserTest {

    protected static final String OIDC_MATCHER_PATH = "/org/geant/idpextension/oidc/attribute/filter/matcher/";

    @Test
    public void policy() throws ComponentInitializationException {

        AttributeInOIDCRequestedClaimsMatcher rule = (AttributeInOIDCRequestedClaimsMatcher) getOIDCMatcher("requestedClaims.xml");
        Assert.assertEquals(rule.getMatchIRequestedClaimsSilent(), true);
        Assert.assertEquals(rule.getMatchOnlyIDToken(), false);
        Assert.assertEquals(rule.getMatchOnlyUserInfo(), true);
        Assert.assertEquals(rule.getOnlyIfEssential(), true);
    }

    protected Matcher getOIDCMatcher(String fileName) throws ComponentInitializationException {

        GenericApplicationContext context = new FilesystemGenericApplicationContext();
        context.setDisplayName("ApplicationContext: Matcher");
        setTestContext(context);

        final String path = OIDC_MATCHER_PATH + fileName;

        final AttributeRule rule = getBean(path, AttributeRule.class, context);

        rule.initialize();
        return rule.getMatcher();

    }

}
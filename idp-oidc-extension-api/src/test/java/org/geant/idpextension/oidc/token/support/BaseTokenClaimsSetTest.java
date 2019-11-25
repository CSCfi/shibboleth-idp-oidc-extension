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

package org.geant.idpextension.oidc.token.support;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import net.minidev.json.JSONArray;
import net.shibboleth.ext.spring.resource.ResourceHelper;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategy;
import net.shibboleth.utilities.java.support.security.DataSealer;
import org.testng.annotations.BeforeMethod;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

import org.springframework.core.io.ClassPathResource;

/**
 * Base for classes testing {@link TokenClaimsSet}.
 */
public class BaseTokenClaimsSetTest {

    protected DataSealer sealer;

    protected String subject = "sub";

    protected String userPrincipal = "userid";

    protected String issuer = "https://op.example.com";

    protected ClientID clientID = new ClientID();

    protected ACR acr = new ACR("0");

    protected Scope scope = new Scope("openid");

    protected Nonce nonce = new Nonce();

    protected ClaimsSet dlClaimsUI = new TokenDeliveryClaimsClaimsSet();

    protected Date iat = new Date();

    protected URI redirectURI;

    protected Date exp = new Date(System.currentTimeMillis() + 30000);

    protected ClaimsSet dlClaims = new TokenDeliveryClaimsClaimsSet();

    protected String idpSessionId = "sessionId";

    protected Date authTime = new Date();

    protected JSONArray consentableClaims = new JSONArray();;

    protected ClaimsSet dlClaimsID = new TokenDeliveryClaimsClaimsSet();

    protected JSONArray consentedClaims = new JSONArray();

    protected ClaimsRequest claims;

    protected String codeChallenge = "code_challenge_123456";

    @BeforeMethod
    protected void setupSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        sealer = new DataSealer();
        final BasicKeystoreKeyStrategy strategy = new BasicKeystoreKeyStrategy();
        strategy.setKeystoreResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.jks")));
        strategy.setKeyVersionResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.kver")));
        strategy.setKeystorePassword("password");
        strategy.setKeyAlias("secret");
        strategy.setKeyPassword("password");
        strategy.initialize();
        sealer.setKeyStrategy(strategy);
        sealer.setRandom(SecureRandom.getInstance("SHA1PRNG"));
        sealer.initialize();
    }

    @BeforeMethod
    protected void setUpParameters() throws Exception {
        redirectURI = new URI("https://rp.example.com/cb");
        claims = new ClaimsRequest();
        claims.addIDTokenClaim("email");
        dlClaims.setClaim("tokenDelivery", "value");
        dlClaimsID.setClaim("tokenToIdtokenDeliveryClaim", "value");
        dlClaimsUI.setClaim("tokenToUserInfotokenDeliveryClaim", "value");
        consentableClaims.add("consentableClaim");
        consentedClaims.add("consentedClaim");
    }
}
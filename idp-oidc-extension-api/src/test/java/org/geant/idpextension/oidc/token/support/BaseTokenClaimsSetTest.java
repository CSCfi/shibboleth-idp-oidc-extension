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
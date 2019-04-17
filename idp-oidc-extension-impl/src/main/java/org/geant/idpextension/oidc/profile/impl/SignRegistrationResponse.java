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

package org.geant.idpextension.oidc.profile.impl;

import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.navigate.OIDCClientRegistrationResponseMetadataLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.MetadataStatementsLookupFunction;
import org.geant.idpextension.oidc.security.impl.CredentialKidUtil;
import org.geant.security.jwk.JWKCredential;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * If metadata_statements already exists in the response metadata, the response is signed according to the OIDCfed
 * specification.
 * 
 * TODO: remove duplicates with other signing actions (id_token issuer).
 * TODO: revisit
 */
@SuppressWarnings("rawtypes")
public class SignRegistrationResponse extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SignRegistrationResponse.class);

    /** The resolved credential. */
    private Credential credential;
    
    /** The response to add the signature on. */
    private OIDCClientInformationResponse response;
    
    /** The value to be used in the 'iss' claim. */
    private String issuer;
    
    /** Stategy used to locate the existing metadata_statements map from the registration response. */
    @Nonnull
    private Function<ProfileRequestContext, Map<String, String>> metadataStatementsLookupStrategy;

    /**
     * Strategy used to locate the {@link SecurityParametersContext} to use for
     * signing.
     */
    @Nonnull
    private Function<ProfileRequestContext, SecurityParametersContext> securityParametersLookupStrategy;

    /** The signature signing parameters. */
    @Nullable
    private SignatureSigningParameters signatureSigningParameters;

    /** Constructor. */
    public SignRegistrationResponse() {
        securityParametersLookupStrategy = new ChildContextLookup<>(SecurityParametersContext.class);
        metadataStatementsLookupStrategy = new MetadataStatementsLookupFunction();
        ((MetadataStatementsLookupFunction)metadataStatementsLookupStrategy).setMetadataLookupStrategy(
                new OIDCClientRegistrationResponseMetadataLookupFunction());
    }

    /**
     * Set the value to be used in the 'iss' claim.
     * @param iss The value to be used in the 'iss' claim.
     */
    public void setIssuer(final String iss) {
        issuer = Constraint.isNotEmpty(iss, "The issuer cannot be empty!");
    }
    
    /**
     * Set the strategy used to locate the {@link SecurityParametersContext} to
     * use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setSecurityParametersLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        securityParametersLookupStrategy = Constraint.isNotNull(strategy,
                "SecurityParameterContext lookup strategy cannot be null");
    }
    
    /**
     * Set the stategy used to locate the existing metadata_statements map from the registration response.
     * @param strategy The stategy used to locate the existing metadata_statements map from the registration response.
     */
    public void setMetadataStatementsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, Map<String, String>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        metadataStatementsLookupStrategy = Constraint.isNotNull(strategy,
                "Metadata statements lookup strategy cannot be null");        
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }

        final SecurityParametersContext secParamCtx = securityParametersLookupStrategy.apply(profileRequestContext);
        if (secParamCtx == null) {
            log.debug("{} Will not sign id token because no security parameters context is available", getLogPrefix());
            return false;
        }

        signatureSigningParameters = secParamCtx.getSignatureSigningParameters();
        if (signatureSigningParameters == null || signatureSigningParameters.getSigningCredential() == null) {
            log.debug("{} Will not sign id token because no signature signing credentials available", getLogPrefix());
            return false;
        }
        credential = signatureSigningParameters.getSigningCredential();

        if (profileRequestContext.getOutboundMessageContext() == null) {
            log.error("{} Unable to locate outbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        final Object message = profileRequestContext.getOutboundMessageContext().getMessage();

        if (message == null || !(message instanceof OIDCClientInformationResponse)) {
            log.error("{} Unable to locate outbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        response = (OIDCClientInformationResponse) message;
        return true;
    }

    /**
     * Returns correct implementation of signer based on algorithm type.
     * 
     * @param jwsAlgorithm
     *            JWS algorithm
     * @return signer for algorithm and private key
     * @throws JOSEException
     *             if algorithm cannot be supported
     */
    private JWSSigner getSigner(Algorithm jwsAlgorithm) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
            return new ECDSASigner((ECPrivateKey) credential.getPrivateKey());
        }
        if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
            return new RSASSASigner(credential.getPrivateKey());
        }
        if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm)) {
            return new MACSigner(credential.getSecretKey());
        }
        throw new JOSEException("Unsupported algorithm " + jwsAlgorithm.getName());
    }

    /**
     * Resolves JWS algorithm from signature signing parameters.
     * 
     * @return JWS algorithm
     */
    private JWSAlgorithm resolveAlgorithm() {

        JWSAlgorithm algorithm = new JWSAlgorithm(signatureSigningParameters.getSignatureAlgorithm());
        if (credential instanceof JWKCredential) {
            if (!algorithm.equals(((JWKCredential) credential).getAlgorithm())) {
                log.warn("{} Signature signing algorithm {} differs from JWK algorithm {}", getLogPrefix(),
                        algorithm.getName(), ((JWKCredential) credential).getAlgorithm());
            }
        }
        log.debug("{} Algorithm resolved {}", getLogPrefix(), algorithm.getName());
        return algorithm;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final OIDCClientMetadata responseMetadata = response.getOIDCClientInformation().getOIDCMetadata();
        
        final Map<String, String> statements = metadataStatementsLookupStrategy.apply(profileRequestContext);
        if (statements == null || statements.isEmpty()) {
            log.debug("{} No existing metadata_statements, nothing to be done", getLogPrefix());
            return;
        }
        
        final String federationId = statements.keySet().iterator().next();

        SignedJWT jwt = null;
        final Algorithm jwsAlgorithm = resolveAlgorithm();
        final String kid = CredentialKidUtil.resolveKid(credential);

        try {
            final JWSSigner signer = getSigner(jwsAlgorithm);
            
            responseMetadata.setCustomField("kid", kid);
            responseMetadata.setCustomField("iss", issuer);
            responseMetadata.setCustomField("exp", 
                    new Long(DateTime.now().plusHours(1).getMillis() / 1000).longValue());
            //TODO: currently hardcoded to one hour, must be configured
            
            jwt = new SignedJWT(new JWSHeader.Builder(new JWSAlgorithm(jwsAlgorithm.getName())).keyID(kid).build(),
                    JWTClaimsSet.parse(response.getOIDCClientInformation().toJSONObject()));
            jwt.sign(signer);
            
            final JSONObject newStatements = new JSONObject();
            newStatements.put(federationId, jwt.serialize());
            
            responseMetadata.setCustomField("metadata_statements", newStatements);
        } catch (ParseException e) {
            log.error("{} Error parsing claimset: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return;
        } catch (JOSEException e) {
            log.error("{} Error signing id token: {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_SIGN);
            return;
        }
        log.debug("{} signed id token stored to context", getLogPrefix());
    }
}
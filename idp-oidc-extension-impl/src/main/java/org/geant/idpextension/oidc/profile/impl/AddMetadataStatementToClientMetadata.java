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

package org.geant.idpextension.oidc.profile.impl;

import java.util.Map;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.context.navigate.MetadataStatementsLookupFunction;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that adds the trusted metadata_statement chain (containing OP's signed key) to the metadata_statement
 * claim in the response metadata.
 * 
 * If the incoming message didn't contain metadata_statement, nothing will be done. If it contained only
 * metadata_statements that are not trusted, an error event is raised. Otherwise, one matching federation is picked
 * by random to the response metadata.
 */
@SuppressWarnings("rawtypes")
public class AddMetadataStatementToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddMetadataStatementToClientMetadata.class);
    
    /** The map of static metadata_statements, key for FO, value for the statement. */
    private Map<String, String> statements;
    
    /** The lookup function for obtaining incoming metadata statements. */
    private Function<ProfileRequestContext,Map<String, String>> statementsLookupFunction;
    
    /**
     * Constructor.
     */
    public AddMetadataStatementToClientMetadata() {
        statementsLookupFunction = new MetadataStatementsLookupFunction();
    }
    
    /**
     * Set the map of static metadata_statements, key for FO, value for the statement.
     * @param metadataStatements The map of static metadata_statements, key for FO, value for the statement.
     */
    public void setMetadataStatements(final Map<String, String> metadataStatements) {
        statements = Constraint.isNotNull(metadataStatements, "The metadata statements cannot be null!");
    }
    
    /**
     * Set the lookup function for obtaining incoming metadata statements.
     * @param function The lookup function for obtaining incoming metadata statements.
     */
    public void setStatementsLookupFunction(final Function<ProfileRequestContext, Map<String, String>> function) {
        statementsLookupFunction = Constraint.isNotNull(function, 
                "The metadata statements lookup function cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Map<String, String> incomingStatements = statementsLookupFunction.apply(profileRequestContext);
        if (incomingStatements == null) {
            log.debug("{} No incoming metadata statements, nothing to do", getLogPrefix());
            return;
        }
        
        for (final String foKey : statements.keySet()) {
            if (incomingStatements.containsKey(foKey)) {
                log.debug("{} Using {} as the federation in the response", getLogPrefix(), foKey);
                final JSONObject statement = new JSONObject();
                statement.put(foKey, statements.get(foKey));
                getOutputMetadata().setCustomField("metadata_statements", statement);
                return;
            }
        }
        
        log.error("{} Could not find any trusted federations from the incoming message", getLogPrefix());
        ActionSupport.buildEvent(this, EventIds.INVALID_MESSAGE);
    }

}
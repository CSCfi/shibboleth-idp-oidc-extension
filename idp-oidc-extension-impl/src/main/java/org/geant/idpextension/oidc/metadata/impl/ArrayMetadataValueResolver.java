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

package org.geant.idpextension.oidc.metadata.impl;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An implementation to {@link MetadataValueResolver} that contains an array of other {@link MetadataValueResolver}s
 * 
 */
public class ArrayMetadataValueResolver extends AbstractIdentifiableInitializableComponent
    implements MetadataValueResolver {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ArrayMetadataValueResolver.class);
    
    /** The name of the JSON object, can be null to return only values of embedded resolvers. */
    private String objectName;
    
    /** The list of resolvers whose value is added to the result of this resolver. */
    private List<MetadataValueResolver> embeddedResolvers;
    
    /** Constructor. */
    public ArrayMetadataValueResolver() {
        objectName = null;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (embeddedResolvers == null) {
            throw new ComponentInitializationException("The list of embedded resolvers cannot be null");
        }
    }
    
    /**
     * Set the list of resolvers whose value is added to the result of this resolver.
     * @param resolvers What to set.
     */
    public void setEmbeddedResolvers(final List<MetadataValueResolver> resolvers) {
        embeddedResolvers = Constraint.isNotNull(resolvers, "The list of embedded resolvers cannot be null");
    }
    
    /**
     * Set the name of the JSON object, can be null to return only values of embedded resolvers.
     * @param name What to set.
     */
    public void setObjectName(final String name) {
        objectName = StringSupport.trimOrNull(name);
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<Object> resolve(ProfileRequestContext profileRequestContext) throws ResolverException {
        final List<Object> result = new ArrayList<>();
        for (final MetadataValueResolver resolver : embeddedResolvers) {
            log.debug("Adding the result from the resolver {}", resolver.getId());
            result.add(resolver.resolveSingle(profileRequestContext));
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public Object resolveSingle(ProfileRequestContext profileRequestContext) throws ResolverException {
        final JSONArray jsonArray = new JSONArray();
        final Iterator<Object> iterator = resolve(profileRequestContext).iterator();
        while (iterator.hasNext()) {
            jsonArray.add(iterator.next());
        }
        if (objectName == null) {
            return jsonArray;            
        } else {
            final JSONObject jsonObject = new JSONObject();
            jsonObject.put(objectName, jsonArray);
            return jsonObject;
        }
    }
}
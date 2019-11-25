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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Helper methods for (OIDC) metadata resolution classes.
 * 
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver} and its parent classes.
 */
public final class ResolverHelper {
    
    /**
     * Constructor.
     */
    private ResolverHelper() {
        // no op
    }
    
    /**
     * Converts an InputStream into a byte array.
     * 
     * @param ins input stream to convert
     * 
     * @return resultant byte array
     * 
     * @throws ResolverException thrown if there is a problem reading the resultant byte array
     */
    public static byte[] inputstreamToByteArray(InputStream ins) throws ResolverException {
        try {
            // 1 MB read buffer
            byte[] buffer = new byte[1024 * 1024];
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            int n = 0;
            while (-1 != (n = ins.read(buffer))) {
                output.write(buffer, 0, n);
            }

            ins.close();
            return output.toByteArray();
        } catch (IOException e) {
            throw new ResolverException(e);
        }
    }
    
    /**
     * Validate the basic properties of the specified metadata file, for example that it exists; 
     * that it is a file; and that it is readable.
     *
     * @param file the file to evaluate
     * @throws ResolverException if file does not pass basic properties required of a metadata file
     */
    public static void validateMetadataFile(@Nonnull final File file) throws ResolverException {
        if (!file.exists()) {
            throw new ResolverException("Metadata file '" + file.getAbsolutePath() + "' does not exist");
        }

        if (!file.isFile()) {
            throw new ResolverException("Metadata file '" + file.getAbsolutePath() + "' is not a file");
        }

        if (!file.canRead()) {
            throw new ResolverException("Metadata file '" + file.getAbsolutePath() + "' is not readable");
        }
    }
}

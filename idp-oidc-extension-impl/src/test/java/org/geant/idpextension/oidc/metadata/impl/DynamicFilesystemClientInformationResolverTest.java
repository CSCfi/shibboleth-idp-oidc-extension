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

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.*;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * Unit tests for {@link DynamicFilesystemClientInformationResolver}.
 */
public class DynamicFilesystemClientInformationResolverTest {

	private static final String METADATA_DIRECTORY = "target/junit-dynamic-metadata-directory";

	private final String clientId = "demo_rp";
	private final String clientId2 = "demo_rp2";
	private final String clientId3 = "demo_rp3";

	private File metadataDirectory;

    private DynamicFilesystemClientInformationResolver resolver;

	private URI redirectUri;
	private URI redirectUri2;
	private URI redirectUri3;

	private void initialize() throws Exception {
		this.redirectUri = new URI("https://192.168.0.150/static");
		this.redirectUri2 = new URI("https://192.168.0.150/static2");
		this.redirectUri3 = new URI("https://192.168.0.150/static3");

		final File file = new File(METADATA_DIRECTORY);
		this.metadataDirectory = file.getAbsoluteFile();

		if (!file.mkdir()) {
		    purgeMetadataDirectory();
        }

		final Resource metadata = new FileSystemResource(file);
		resolver = new DynamicFilesystemClientInformationResolver(metadata);
		resolver.setId(METADATA_DIRECTORY);
		resolver.initialize();
	}

	private void destroy() {
		resolver.destroy();
        purgeMetadataDirectory();
		Assert.assertTrue(metadataDirectory.delete());
	}

	@Test
	public void test() throws Exception {
		// initialize DynamicFilesystemClientInformationResolver and setup test directory
		initialize();

		// must not contain no client metadata
		Assert.assertNull(resolve(clientId));
		Assert.assertNull(resolve(clientId2));
		Assert.assertNull(resolve(clientId3));

		// create new metadata file
        final String oidc_client3_json = this.metadataDirectory.getAbsolutePath() + "/oidc-client3.json";
		copy(
		        "/org/geant/idpextension/oidc/metadata/impl/oidc-client3.json",
                oidc_client3_json);
		waitForDirectoryWatcher();

		// must only contain demo_rp3
		Assert.assertNotNull(resolve(clientId3));
		Assert.assertNull(resolve(clientId));
		Assert.assertNull(resolve(clientId2));

		// create new metadata file with multiple clients
        final String oidc_clients_json = this.metadataDirectory.getAbsolutePath() + "/oidc-clients.json";
		copy(
		        "/org/geant/idpextension/oidc/metadata/impl/oidc-clients.json",
                oidc_clients_json);
        waitForDirectoryWatcher();

        // must contain demo_rp, demo_rp2 and demo_rp3
        Assert.assertNotNull(resolve(clientId));
		Assert.assertNotNull(resolve(clientId2));
        Assert.assertNotNull(resolve(clientId3));

        // modify metadata file
        final String replacement = "newstatic";
        replace(oidc_clients_json, "static2", replacement);
        waitForDirectoryWatcher();

        // must contain updated client information
        final OIDCClientInformation clientInformation = resolve(clientId2);
        Assert.assertNotNull(clientInformation);
		final Set<URI> redirectUris = clientInformation.getOIDCMetadata().getRedirectionURIs();
		Assert.assertNotNull(redirectUris);
		Assert.assertTrue(redirectUris.iterator().hasNext());
		final URI uri = redirectUris.iterator().next();
		Assert.assertNotNull(uri);
        Assert.assertTrue(uri.toString().contains(replacement));

        // remove metadata file
		final File deleted = new File(oidc_client3_json);
		Assert.assertTrue(deleted.delete());
		waitForDirectoryWatcher();

		// must not contain demo_rp3
		Assert.assertNull(resolve(clientId3));
		Assert.assertNotNull(resolve(clientId));
		Assert.assertNotNull(resolve(clientId2));

		// destroy DynamicFilesystemClientInformationResolver and cleanup test directory
		destroy();
	}

	private OIDCClientInformation resolve(final String clientId) {
		final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID(clientId));
		try {
			return resolver.resolveSingle(new CriteriaSet(criterion));
		} catch (final Exception e) {
			return null;
		}
	}

    private void purgeMetadataDirectory() {
        final File[] metadataFiles = metadataDirectory.listFiles();
        if (metadataFiles != null) {
            for (final File metadataFile : metadataFiles) {
                Assert.assertTrue(metadataFile.delete());
            }
        }
    }

	private static void copy(final String classpathPath, final String filesystemPath) throws FileNotFoundException {
		try {
			final InputStream in = DynamicFilesystemClientInformationResolverTest.class.getResourceAsStream(classpathPath);
			Files.copy(in, Paths.get(filesystemPath + "/"));
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

	private static void replace(final String file, final String regex, final String replacement) {
        Path path = Paths.get(file);
        Charset charset = StandardCharsets.UTF_8;

        try {
            String content = new String(Files.readAllBytes(path), charset);
            content = content.replaceAll(regex, replacement);
            Files.write(path, content.getBytes(charset));
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

	private static void waitForDirectoryWatcher() {
		try {
			Thread.sleep(1000L);
		} catch (final InterruptedException e) {
			e.printStackTrace();
		}
	}
}

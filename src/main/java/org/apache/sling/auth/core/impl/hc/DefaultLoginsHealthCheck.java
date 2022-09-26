/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.sling.auth.core.impl.hc;

import java.util.Arrays;
import java.util.List;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;

import org.apache.felix.hc.api.FormattingResultLog;
import org.apache.felix.hc.api.HealthCheck;
import org.apache.felix.hc.api.Result;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link HealthCheck} that runs an arbitrary script. */
@Component(service = HealthCheck.class, name = "org.apache.sling.auth.core.DefaultLoginsHealthCheck", configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = DefaultLoginsHealthCheck.Config.class, factory = true)
public class DefaultLoginsHealthCheck implements HealthCheck {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultLoginsHealthCheck.class);

    public static final String HC_LABEL = "Health Check: Default Logins";

    @ObjectClassDefinition(name = HC_LABEL, description = "Expects default logins to fail, used to verify that they are disabled on production systems")
    @interface Config {

        @AttributeDefinition(name = "Name", description = "Name of this health check.")
        String hc_name() default "Default Logins Check"; // NOSONAR

        @AttributeDefinition(name = "Tags", description = "List of tags for this health check, used to select subsets of health checks for execution e.g. by a composite health check.")
        String[] hc_tags() default {}; // NOSONAR

        @AttributeDefinition(name = "Default Logins", description = "Which credentials to check. Each one is in the format"
                + " \"user:password\" like \"admin:admin\" for example. Do *not* put any confidential passwords here, the goal "
                + "is just to check that the default/demo logins, which passwords are known anyway, are disabled.")
        String[] logins() default "logins";

        @AttributeDefinition
        String webconsole_configurationFactory_nameHint() default "Default Logins Check: {logins}"; // NOSONAR
    }

    private List<String> logins;

    @Reference
    private SlingRepository repository;

    @Activate
    protected void activate(Config config) {
        this.logins = Arrays.asList(config.logins());
        LOG.info("Activated, logins={}", logins);
    }

    @Override
    public Result execute() {
        FormattingResultLog resultLog = new FormattingResultLog();
        int checked = 0;
        int failures = 0;

        for (String login : logins) {
            final String[] parts = login.split(":");
            if (parts.length != 2) {
                resultLog.warn("Expected login in the form username:password, got [{}]", login);
                continue;
            }
            checked++;
            final String username = parts[0].trim();
            final String password = parts[1].trim();
            final Credentials creds = new SimpleCredentials(username, password.toCharArray());
            Session s = null;
            try {
                s = repository.login(creds);
                if (s != null) {
                    failures++;
                    resultLog.warn("Login as [{}] succeeded, was expecting it to fail", username);
                } else {
                    resultLog.debug("Login as [{}] didn't throw an Exception but returned null Session", username);
                }
            } catch (RepositoryException re) {
                resultLog.debug("Login as [{}] failed, as expected", username);
            } finally {
                if (s != null) {
                    s.logout();
                }
            }
        }

        if (checked == 0) {
            resultLog.warn("Did not check any logins, configured logins={}", logins);
        } else if (failures != 0) {
            resultLog.warn("Checked {} logins, {} failures", checked, failures);
        } else {
            resultLog.debug("Checked {} logins, all successful", checked, failures);
        }

        return new Result(resultLog);
    }

}

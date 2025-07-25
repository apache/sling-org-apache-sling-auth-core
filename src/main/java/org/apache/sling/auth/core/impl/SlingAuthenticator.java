/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.core.impl;

import java.io.Closeable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestEvent;
import jakarta.servlet.ServletRequestListener;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.api.SlingConstants;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.auth.NoAuthenticationHandlerException;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.wrappers.JakartaToJavaxRequestWrapper;
import org.apache.sling.api.wrappers.JakartaToJavaxResponseWrapper;
import org.apache.sling.api.wrappers.JavaxToJakartaRequestWrapper;
import org.apache.sling.api.wrappers.JavaxToJakartaResponseWrapper;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.JakartaLoginEventDecorator;
import org.apache.sling.auth.core.LoginEventDecorator;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler.FAILURE_REASON_CODES;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.apache.sling.auth.core.spi.DefaultJakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationInfoPostProcessor;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.FieldOption;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.osgi.service.component.propertytypes.ServiceVendor;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventAdmin;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.osgi.service.metatype.annotations.Option;
import org.osgi.service.servlet.context.ServletContextHelper;
import org.osgi.service.servlet.whiteboard.HttpWhiteboardConstants;
import org.osgi.service.servlet.whiteboard.propertytypes.HttpWhiteboardContextSelect;
import org.osgi.service.servlet.whiteboard.propertytypes.HttpWhiteboardListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <code>SlingAuthenticator</code> class is the default implementation for
 * handling authentication. This class supports :
 * <ul>
 * <li>Support for login sessions where session ids are exchanged with cookies
 * <li>Support for multiple authentication handlers, which must implement the
 * {@link JakartaAuthenticationHandler} interface.
 * <li>
 * </ul>
 * <p>
 * Currently this class does not support multiple handlers for any one request
 * URL.
 */
@Component(
        name = SlingAuthenticator.PID,
        service = {Authenticator.class, AuthenticationSupport.class, ServletRequestListener.class})
@HttpWhiteboardContextSelect("(" + HttpWhiteboardConstants.HTTP_WHITEBOARD_CONTEXT_NAME + "=*)")
@HttpWhiteboardListener
@ServiceDescription("Apache Sling Request Authenticator")
@ServiceVendor("The Apache Software Foundation")
@Designate(ocd = SlingAuthenticator.Config.class)
public class SlingAuthenticator implements Authenticator, AuthenticationSupport, ServletRequestListener {

    /** The pid for the configuration */
    public static final String PID = "org.apache.sling.engine.impl.auth.SlingAuthenticator";

    @ObjectClassDefinition(
            name = "Apache Sling Authentication Service",
            description = "Extracts user authentication details from the request with"
                    + " the help of authentication handlers registered as separate services. One"
                    + " example of such an authentication handler is the handler HTTP Authorization"
                    + " header contained authentication.")
    public @interface Config {

        @AttributeDefinition(
                name = "Impersonation Cookie",
                description = "The name the HTTP Cookie to set with the value"
                        + " of the user which is to be impersonated. This cookie will always be a session"
                        + " cookie.")
        String auth_sudo_cookie() default "sling.sudo"; // NOSONAR

        @AttributeDefinition(
                name = "Impersonation Parameter",
                description = "The name of the request parameter initiating"
                        + " impersonation. Setting this parameter to a user id will result in using an"
                        + " impersonated session (instead of the actually authenticated session) and set"
                        + " a session cookie of the name defined in the Impersonation Cookie setting.")
        String auth_sudo_parameter() default "sudo"; // NOSONAR

        @AttributeDefinition(
                name = "Allow Anonymous Access",
                description = "Whether default access as anonymous when no"
                        + " credentials are present in the request is allowed. The default value is"
                        + " \"true\" to allow access without credentials. When set to \"false\" access to the"
                        + " repository is only allowed if valid credentials are presented. The value of"
                        + " this configuration option is added to list of Authentication Requirements"
                        + " and needs not be explicitly listed. If anonymous access is allowed the entry"
                        + " added is \"-/\". Otherwise anonymous access is denied and \"+/\" is added to the"
                        + " list.")
        boolean auth_annonymous() default true; // NOSONAR

        @AttributeDefinition(
                name = "Authentication Requirements",
                description = "Defines URL space subtrees which require"
                        + " or don't require authentication. For any request the best matching path"
                        + " configured applies and defines whether authentication is actually required"
                        + " for the request or not. Each entry in this list can be an absolute path (such"
                        + " as /content) or and absolute URI (such as http://thehost/content). Optionally"
                        + " each entry may be prefixed by a plus (+) or minus (-) sign indicating that"
                        + " authentication is required (plus) or not required (minus). Example entries are"
                        + " \"/content\" or \"+/content\" to require authentication at and below \"/content\" and"
                        + " \"-/system/sling/login\" to not require authentication at and below"
                        + " \"/system/sling/login\". By default this list is empty. This list is extended at"
                        + " run time with additional entries: One entry is added for the \"Allow Anonymous"
                        + " Access\" configuration. Other entries are added for any services setting the"
                        + " \"sling.auth.requirements\" service registration property.")
        String[] sling_auth_requirements(); // NOSONAR

        @AttributeDefinition(
                name = "Anonymous User Name",
                description = "Defines which user name to assume"
                        + " for anonymous requests, that is requests not providing credentials"
                        + " supported by any of the registered authentication handlers. If this"
                        + " property is missing or empty, the default is assumed which depends on"
                        + " the resource provider(s). Otherwise anonymous requests are handled with"
                        + " this user name. If the configured user name does not exist or is not"
                        + " allowed to access the resource data, anonymous requests may still be"
                        + " blocked. If anonymous access is not allowed, this property is ignored.")
        String sling_auth_anonymous_user(); // NOSONAR

        @AttributeDefinition(
                name = "Anonymous User Password",
                description = "Password for the anonymous"
                        + " user defined in the Anonymous User Name field. This property is only"
                        + " used if a non-empty anonymous user name is configured. If this property"
                        + " is not defined but a password is required, an empty password would be"
                        + " assumed.",
                type = AttributeType.PASSWORD)
        String sling_auth_anonymous_password(); // NOSONAR

        @AttributeDefinition(
                name = "HTTP Basic Authentication",
                description = "Level of support for HTTP Basic Authentication. Such"
                        + " support can be provided in three levels: (1) no support at all, that is"
                        + " disabled, (2) preemptive support, that is HTTP Basic Authentication is"
                        + " supported if the authentication header is set in the request, (3) full"
                        + " support. The default is preemptive support unless Anonymous Access is"
                        + " not allowed. In this case HTTP Basic Authentication is always enabled"
                        + " to ensure clients can authenticate at least with basic authentication.",
                options = {
                    @Option(label = "Enabled", value = HTTP_AUTH_ENABLED),
                    @Option(label = "Enabled (Preemptive)", value = HTTP_AUTH_PREEMPTIVE),
                    @Option(label = "Disabled", value = HTTP_AUTH_DISABLED)
                })
        String auth_http() default HTTP_AUTH_PREEMPTIVE; // NOSONAR

        @AttributeDefinition(
                name = "Realm",
                description = "HTTP BASIC authentication realm. This property"
                        + " is only used if the HTTP Basic Authentication support is not disabled. The"
                        + " default value is \"Sling (Development)\".")
        String auth_http_realm() default "Sling (Development)"; // NOSONAR

        @AttributeDefinition(
                name = "Authentication URI Suffices",
                description = "A list of request URI suffixes intended to"
                        + " be handled by Authentication Handlers. Any request whose request URI"
                        + " ends with any one of the listed suffices is intended to be handled by"
                        + " an Authentication Handler causing the request to either be rejected or"
                        + " the client being redirected to another location and thus the request not"
                        + " being further processed after the authentication phase. The default is"
                        + " just \"/j_security_check\" which is the suffix defined by the Servlet API"
                        + " specification used for FORM based authentication.")
        String[] auth_uri_suffix() default DEFAULT_AUTH_URI_SUFFIX; // NOSONAR
    }

    /** default logger */
    private final Logger log = LoggerFactory.getLogger(SlingAuthenticator.class);

    /**
     * Value of the {@link Config#auth_http()} property to fully enable the built-in
     * HTTP Authentication Handler (value is "enabled").
     */
    static final String HTTP_AUTH_ENABLED = "enabled";

    /**
     * Value of the {@link Config#auth_http()} property to completely disable the
     * built-in HTTP Authentication Handler (value is "disabled").
     */
    static final String HTTP_AUTH_DISABLED = "disabled";

    /**
     * Value of the {@link Config#auth_http()} property to enable extracting the
     * credentials if the HTTP Basic authentication header is present (value is
     * "preemptive"). In <i>preemptive</i> mode, though, the
     * <code>requestCredentials</code> and <code>dropCredentials</code> methods
     * will not send back a 401 response.
     */
    static final String HTTP_AUTH_PREEMPTIVE = "preemptive";

    /**
     * Default request URI suffix to expect to be handled by authentication
     * handlers and not expecting to cause
     * {@link #handleSecurity(HttpServletRequest, HttpServletResponse)} to
     * return <code>true</code>.
     */
    static final String DEFAULT_AUTH_URI_SUFFIX = "/j_security_check";

    /**
     * The name of the form submission parameter providing the new password of
     * the user (value is "j_newpassword").
     */
    private static final String PAR_NEW_PASSWORD = "j_newpassword";

    /**
     * The name of the {@link AuthenticationInfo} property providing the option
     * {@link org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler}
     * handler to be called back on login failure or success.
     */
    private static final String AUTH_INFO_PROP_FEEDBACK_HANDLER = "$$sling.auth.AuthenticationFeedbackHandler$$";

    /** The name of the impersonation parameter */
    private volatile String sudoParameterName;

    /** The name of the impersonation cookie */
    private volatile String sudoCookieName;

    /**
     * The configured URI suffices indicating a authentication requests and
     * requiring redirects and thus returning <code>false</code> from the
     * #handleSecurity method.
     * <p>
     * This will be <code>null</code> if there are no suffices to consider.
     */
    private volatile String[] authUriSuffices; // NOSONAR

    /**
     * The name of the user to assume for anonymous access. By default this is
     * <code>null</code> to use <code>null</code> credentials and thus use the
     * system provided identification.
     *
     * @see #getAnonymousCredentials()
     */
    private volatile String anonUser;

    /**
     * The password to use for anonymous access. This property is only used if
     * the {@link #anonUser} field is not <code>null</code>.
     *
     * @see #getAnonymousCredentials()
     */
    private volatile char[] anonPassword; // NOSONAR

    /** HTTP Basic authentication handler */
    private volatile HttpBasicAuthenticationHandler httpBasicHandler; // NOSONAR

    /**
     * The manager for services registered with "sling.auth.requirements" to
     * update the internal authentication requirements
     */
    private final PathBasedHolderCache<AuthenticationRequirementHolder> authenticationRequirementsManager;

    /**
     * Manager for authentication handlers.
     */
    private final PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authHandlersManager;

    /**
     * JakartaAuthenticationInfoPostProcessor services
     */
    @Reference(
            cardinality = ReferenceCardinality.MULTIPLE,
            service = JakartaAuthenticationInfoPostProcessor.class,
            fieldOption = FieldOption.REPLACE)
    private volatile List<JakartaAuthenticationInfoPostProcessor> jakartaAuthInfoPostProcessors =
            Collections.emptyList(); // NOSONAR

    /**
     * AuthenticationInfoPostProcessor services
     */
    @SuppressWarnings("deprecation")
    @Reference(
            cardinality = ReferenceCardinality.MULTIPLE,
            service = AuthenticationInfoPostProcessor.class,
            fieldOption = FieldOption.REPLACE)
    private volatile List<AuthenticationInfoPostProcessor> authInfoPostProcessors = Collections.emptyList(); // NOSONAR

    /**
     * The event admin service.
     */
    @Reference(
            policy = ReferencePolicy.DYNAMIC,
            cardinality = ReferenceCardinality.OPTIONAL,
            policyOption = ReferencePolicyOption.GREEDY)
    private volatile EventAdmin eventAdmin; // NOSONAR

    @Reference(
            policy = ReferencePolicy.DYNAMIC,
            cardinality = ReferenceCardinality.OPTIONAL,
            policyOption = ReferencePolicyOption.GREEDY)
    private volatile SlingAuthenticationMetrics metricsService;

    private final ResourceResolverFactory resourceResolverFactory;

    /**
     * LoginEventDecorator services
     */
    @Reference(
            cardinality = ReferenceCardinality.MULTIPLE,
            service = JakartaLoginEventDecorator.class,
            fieldOption = FieldOption.REPLACE)
    private volatile List<JakartaLoginEventDecorator> jakartaLoginEventDecorators = new ArrayList<>(); // NOSONAR

    /**
     * LoginEventDecorator services
     */
    @SuppressWarnings("deprecation")
    @Reference(
            cardinality = ReferenceCardinality.MULTIPLE,
            service = LoginEventDecorator.class,
            fieldOption = FieldOption.REPLACE)
    private volatile List<LoginEventDecorator> loginEventDecorators = new ArrayList<>(); // NOSONAR

    // ---------- SCR integration

    @Activate
    public SlingAuthenticator(
            @Reference AuthenticationRequirementsManager authReqManager,
            @Reference AuthenticationHandlersManager authHandlerManager,
            @Reference(policyOption = ReferencePolicyOption.GREEDY)
                    final ResourceResolverFactory resourceResolverFactory,
            final BundleContext bundleContext,
            final Config config) {
        this.resourceResolverFactory = resourceResolverFactory;

        this.authenticationRequirementsManager = authReqManager;
        this.authHandlersManager = authHandlerManager;
        this.modified(config);
    }

    @Modified
    private void modified(final Config config) {
        if (!config.auth_sudo_cookie().equals(this.sudoCookieName)) {
            log.info(
                    "modified: Setting new cookie name for impersonation {} (was {})",
                    config.auth_sudo_cookie(),
                    this.sudoCookieName);
            this.sudoCookieName = config.auth_sudo_cookie();
        }

        if (!config.auth_sudo_parameter().equals(this.sudoParameterName)) {
            log.info(
                    "modified: Setting new parameter name for impersonation {} (was {})",
                    config.auth_sudo_parameter(),
                    this.sudoParameterName);
            this.sudoParameterName = config.auth_sudo_parameter();
        }

        if (config.sling_auth_anonymous_user() != null
                && config.sling_auth_anonymous_user().length() > 0) {
            this.anonUser = config.sling_auth_anonymous_user();
            this.anonPassword = config.sling_auth_anonymous_password() == null
                    ? "".toCharArray()
                    : config.sling_auth_anonymous_password().toCharArray();
        } else {
            this.anonUser = null;
            this.anonPassword = null;
        }

        this.authUriSuffices = config.auth_uri_suffix();

        if (!config.auth_annonymous()) {
            log.info("modified: Anonymous Access is denied thus HTTP Basic Authentication is fully enabled");
        }

        final String http = getHttpAuth(config);
        if (HTTP_AUTH_DISABLED.equals(http)) {
            this.httpBasicHandler = null;
        } else {
            this.httpBasicHandler =
                    new HttpBasicAuthenticationHandler(config.auth_http_realm(), HTTP_AUTH_ENABLED.equals(http));
        }
    }

    /**
     * Get the configuration for the http auth
     * @param config The configuration
     * @return The http auth
     */
    public static String getHttpAuth(final Config config) {
        final String http;
        if (config.auth_annonymous()) {
            http = config.auth_http();
        } else {
            http = HTTP_AUTH_ENABLED;
        }

        return http;
    }

    // --------- AuthenticationSupport interface

    /**
     * Checks the authentication contained in the request. This check is only
     * based on the original request object, no URI translation has taken place
     * yet.
     * <p>
     *
     * @param request The request object containing the information for the
     *            authentication.
     * @param response The response object which may be used to send the
     *            information on the request failure to the user.
     * @return <code>true</code> if request processing should continue assuming
     *         successful authentication. If <code>false</code> is returned it
     *         is assumed a response has been sent to the client and the request
     *         is terminated.
     */
    @Override
    public boolean handleSecurity(HttpServletRequest request, HttpServletResponse response) {
        // 0. Nothing to do, if the session is also in the request
        // this might be the case if the request is handled as a result
        // of a servlet container include inside another Sling request
        Object sessionAttr = request.getAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        if (sessionAttr instanceof ResourceResolver) {
            log.debug("handleSecurity: Request already authenticated, nothing to do");
            return true;
        } else if (sessionAttr != null) {
            // warn and remove existing non-session
            log.warn("handleSecurity: Overwriting existing ResourceResolver attribute ({})", sessionAttr);
            request.removeAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        }

        boolean process = false;
        final SlingAuthenticationMetrics local = this.metricsService;
        final Closeable ctx = local != null ? local.authenticationTimerContext() : null;
        try {
            process = doHandleSecurity(request, response);
            if (process && expectAuthenticationHandler(request)) {
                log.warn("handleSecurity: AuthenticationHandler did not block request; access denied");
                request.removeAttribute(JakartaAuthenticationHandler.FAILURE_REASON);
                request.removeAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE);
                AuthUtil.sendInvalid(request, response);
                process = false;
            }
        } finally {
            if (local != null) {
                try {
                    ctx.close();
                } catch (final IOException e) {
                    // ignore
                }
                local.authenticateCompleted(process);
            }
        }
        return process;
    }

    private boolean doHandleSecurity(HttpServletRequest request, HttpServletResponse response) {

        // 0. Check for request attribute; set if not present
        Object authUriSufficesAttr = request.getAttribute(AuthConstants.ATTR_REQUEST_AUTH_URI_SUFFIX);
        if (authUriSufficesAttr == null && authUriSuffices != null) {
            request.setAttribute(AuthConstants.ATTR_REQUEST_AUTH_URI_SUFFIX, authUriSuffices);
        }

        // 1. Ask all authentication handlers to try to extract credentials
        final AuthenticationInfo authInfo = getAuthenticationInfo(request, response);

        // 2. PostProcess credentials
        try {
            postProcess(authInfo, request, response);
        } catch (LoginException e) {
            postLoginFailedEvent(request, authInfo, e);

            handleLoginFailure(request, response, authInfo, e);
            return false;
        }

        // 3. Check Credentials
        if (authInfo == AuthenticationInfo.DOING_AUTH) {

            log.debug("doHandleSecurity: ongoing authentication in the handler");
            return false;

        } else if (authInfo == AuthenticationInfo.FAIL_AUTH) {

            log.debug("doHandleSecurity: Credentials present but not valid, request authentication again");
            AuthUtil.setLoginResourceAttribute(request, request.getRequestURI());
            doLogin(request, response);
            return false;

        } else if (authInfo.getAuthType() == null) {

            log.debug("doHandleSecurity: No credentials in the request, anonymous");
            return getAnonymousResolver(request, response, authInfo);

        } else {

            log.debug("doHandleSecurity: Trying to get a session for {}", authInfo.getUser());
            return getResolver(request, response, authInfo);
        }
    }

    @Override
    public void finishSecurity(HttpServletRequest request, HttpServletResponse response) {
        Object resolverAttr = request.getAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        if (resolverAttr instanceof ResourceResolver) {
            ((ResourceResolver) resolverAttr).close();
            request.removeAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        }
    }

    // ---------- Authenticator interface

    /**
     * Requests authentication information from the client. Returns
     * <code>true</code> if the information has been requested and request
     * processing can be terminated. Otherwise the request information could not
     * be requested and the request should be terminated with a 403/FORBIDDEN
     * response.
     * <p>
     * Any response sent by the handler is also handled by the error handler
     * infrastructure.
     *
     * @param request The request object
     * @param response The response object to which to send the request
     * @throws IllegalStateException If response is already committed
     * @throws NoAuthenticationHandlerException If no authentication handler
     *             claims responsibility to authenticate the request.
     */
    @Override
    public void login(HttpServletRequest request, HttpServletResponse response) {

        // ensure the response is not committed yet
        if (response.isCommitted()) {
            throw new IllegalStateException("Response already committed");
        }

        // select path used for authentication handler selection
        final Collection<AbstractAuthenticationHandlerHolder>[] holdersArray =
                this.authHandlersManager.findApplicableHolders(request);
        final String path = getHandlerSelectionPath(request);
        boolean done = false;
        for (int m = 0; !done && m < holdersArray.length; m++) {
            final Collection<AbstractAuthenticationHandlerHolder> holderList = holdersArray[m];
            if (holderList != null) {
                for (AbstractAuthenticationHandlerHolder holder : holderList) {
                    if (holder.isPathRequiresHandler(path)) {
                        log.debug("login: requesting authentication using handler: {}", holder);

                        try {
                            done = holder.requestCredentials(request, response);
                        } catch (IOException ioe) {
                            log.error(
                                    "login: Failed sending authentication request through handler " + holder
                                            + ", access forbidden",
                                    ioe);
                            done = true;
                        }
                        if (done) {
                            break;
                        }
                    }
                }
            }
        }

        // fall back to HTTP Basic handler (if not done already)
        if (!done && httpBasicHandler != null) {
            done = httpBasicHandler.requestCredentials(request, response);
        }

        // no handler could send an authentication request, throw
        if (!done) {
            int size = 0;
            for (int m = 0; m < holdersArray.length; m++) {
                if (holdersArray[m] != null) {
                    size += holdersArray[m].size();
                }
            }
            log.info("login: No handler for request ({} handlers available)", size);
            throw new NoAuthenticationHandlerException();
        }
    }

    /**
     * Logs out the user calling all applicable
     * {@link org.apache.sling.auth.core.spi.AuthenticationHandler}
     * authentication handlers.
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {

        // ensure the response is not committed yet
        if (response.isCommitted()) {
            throw new IllegalStateException("Response already committed");
        }

        // make sure impersonation is dropped
        setSudoCookie(request, response, new AuthenticationInfo("dummy", request.getRemoteUser()));

        final String path = getHandlerSelectionPath(request);
        final Collection<AbstractAuthenticationHandlerHolder>[] holdersArray =
                this.authHandlersManager.findApplicableHolders(request);
        for (int m = 0; m < holdersArray.length; m++) {
            final Collection<AbstractAuthenticationHandlerHolder> holderSet = holdersArray[m];
            if (holderSet != null) {
                for (AbstractAuthenticationHandlerHolder holder : holderSet) {
                    if (holder.isPathRequiresHandler(path)) {
                        log.debug("logout: dropping authentication using handler: {}", holder);

                        try {
                            holder.dropCredentials(request, response);
                        } catch (IOException ioe) {
                            log.error("logout: Failed dropping authentication through handler " + holder, ioe);
                        }
                    }
                }
            }
        }

        if (httpBasicHandler != null) {
            httpBasicHandler.dropCredentials(request, response);
        }

        redirectAfterLogout(request, response);
    }

    @Override
    public void login(
            final javax.servlet.http.HttpServletRequest request,
            final javax.servlet.http.HttpServletResponse response) {
        this.login(
                JavaxToJakartaRequestWrapper.toJakartaRequest(request),
                JavaxToJakartaResponseWrapper.toJakartaResponse(response));
    }

    @Override
    public void logout(
            final javax.servlet.http.HttpServletRequest request,
            final javax.servlet.http.HttpServletResponse response) {
        this.logout(
                JavaxToJakartaRequestWrapper.toJakartaRequest(request),
                JavaxToJakartaResponseWrapper.toJakartaResponse(response));
    }

    @Override
    public boolean handleSecurity(
            final javax.servlet.http.HttpServletRequest request,
            final javax.servlet.http.HttpServletResponse response) {
        return this.handleSecurity(
                JavaxToJakartaRequestWrapper.toJakartaRequest(request),
                JavaxToJakartaResponseWrapper.toJakartaResponse(response));
    }

    // ---------- ServletRequestListener

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        // don't care
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        ServletRequest request = sre.getServletRequest();
        Object resolverAttr = request.getAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        if (resolverAttr instanceof ResourceResolver) {
            ((ResourceResolver) resolverAttr).close();
            request.removeAttribute(REQUEST_ATTRIBUTE_RESOLVER);
        }
    }

    // ---------- internal

    /**
     * Get the request path from the request
     * @param request The request
     * @return The path
     */
    private String getPath(final HttpServletRequest request) {
        final StringBuilder sb = new StringBuilder();
        if (request.getServletPath() != null) {
            sb.append(request.getServletPath());
        }
        if (request.getPathInfo() != null) {
            sb.append(request.getPathInfo());
        }
        String path = sb.toString();
        // Get the path used to select the authenticator, if the SlingServlet
        // itself has been requested without any more info, this will be empty
        // and we assume the root (SLING-722)
        if (path.length() == 0) {
            path = "/";
        }

        return path;
    }

    private AuthenticationInfo getAuthenticationInfo(HttpServletRequest request, HttpServletResponse response) {

        String path = getPath(request);

        final Collection<AbstractAuthenticationHandlerHolder>[] localArray =
                this.authHandlersManager.findApplicableHolders(request);
        for (int m = 0; m < localArray.length; m++) {
            final Collection<AbstractAuthenticationHandlerHolder> local = localArray[m];
            if (local != null) {
                for (AbstractAuthenticationHandlerHolder holder : local) {
                    if (holder.isPathRequiresHandler(path)) {
                        final AuthenticationInfo authInfo = holder.extractCredentials(request, response);
                        if (authInfo != null) {
                            // skip the put call for known read-only objects
                            if (authInfo != AuthenticationInfo.DOING_AUTH && authInfo != AuthenticationInfo.FAIL_AUTH) {
                                // add the feedback handler to the info (may be null)
                                authInfo.put(AUTH_INFO_PROP_FEEDBACK_HANDLER, holder.getFeedbackHandler());
                            }
                            return authInfo;
                        }
                    }
                }
            }
        }

        // check whether the HTTP Basic handler can extract the header
        if (httpBasicHandler != null) {
            final AuthenticationInfo authInfo = httpBasicHandler.extractCredentials(request, response);
            if (authInfo != null) {
                authInfo.put(AUTH_INFO_PROP_FEEDBACK_HANDLER, httpBasicHandler);
                return authInfo;
            }
        }

        // no handler found for the request ....
        log.debug("getAuthenticationInfo: no handler could extract credentials; assuming anonymous");
        return getAnonymousCredentials();
    }

    /**
     * Run through the available post processors.
     */
    @SuppressWarnings("deprecation")
    private void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response)
            throws LoginException {
        final List<JakartaAuthenticationInfoPostProcessor> localList = this.jakartaAuthInfoPostProcessors;
        for (final JakartaAuthenticationInfoPostProcessor processor : localList) {
            processor.postProcess(info, request, response);
        }
        final List<AuthenticationInfoPostProcessor> localListDep = this.authInfoPostProcessors;
        for (final AuthenticationInfoPostProcessor processor : localListDep) {
            processor.postProcess(
                    info,
                    JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                    JakartaToJavaxResponseWrapper.toJavaxResponse(response));
        }
    }

    /**
     * Try to acquire a ResourceResolver as indicated by authInfo
     *
     * @return <code>true</code> if request processing should continue assuming
     *         successful authentication. If <code>false</code> is returned it
     *         is assumed a response has been sent to the client and the request
     *         is terminated.
     */
    private boolean getResolver(
            final HttpServletRequest request, final HttpServletResponse response, final AuthenticationInfo authInfo) {

        // prepare the feedback handler
        final JakartaAuthenticationFeedbackHandler feedbackHandler =
                (JakartaAuthenticationFeedbackHandler) authInfo.remove(AUTH_INFO_PROP_FEEDBACK_HANDLER);
        final Object sendLoginEvent = authInfo.remove(AuthConstants.AUTH_INFO_LOGIN);

        // try to connect
        try {
            handleImpersonation(request, authInfo);
            handlePasswordChange(request, authInfo);
            ResourceResolver resolver = resourceResolverFactory.getResourceResolver(authInfo);
            final boolean impersChanged = setSudoCookie(request, response, authInfo);

            if (sendLoginEvent != null) {
                postLoginEvent(request, authInfo);
            }

            // provide the resource resolver to the feedback handler
            request.setAttribute(REQUEST_ATTRIBUTE_RESOLVER, resolver);

            boolean processRequest = true;

            // custom feedback handler with option to redirect
            if (feedbackHandler != null) {
                processRequest = !feedbackHandler.authenticationSucceeded(request, response, authInfo);
            }

            if (processRequest) {
                if (AuthUtil.isValidateRequest(request)) {
                    AuthUtil.sendValid(response);
                    processRequest = false;
                } else if (impersChanged || feedbackHandler == null) {
                    processRequest = !DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response);
                }
            }

            if (processRequest) {
                // process: set required attributes
                setAttributes(resolver, authInfo.getAuthType(), request);
            } else {
                // terminate: cleanup
                resolver.close();
            }

            return processRequest;

        } catch (LoginException re) {
            postLoginFailedEvent(request, authInfo, re);

            // handle failure feedback before proceeding to handling the
            // failed login internally
            if (feedbackHandler != null) {
                feedbackHandler.authenticationFailed(request, response, authInfo);
            }

            // now find a way to get credentials unless the feedback handler
            // has committed a response to the client already
            if (!response.isCommitted()) {
                return handleLoginFailure(request, response, authInfo, re);
            }
        }

        // end request
        return false;
    }

    private boolean expectAuthenticationHandler(final HttpServletRequest request) {
        if (this.authUriSuffices != null) {
            final String requestUri = request.getRequestURI();
            for (final String uriSuffix : this.authUriSuffices) {
                if (requestUri.endsWith(uriSuffix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Try to acquire an anonymous ResourceResolver */
    private boolean getAnonymousResolver(
            final HttpServletRequest request, final HttpServletResponse response, final AuthenticationInfo authInfo) {

        // Get an anonymous session if allowed, or if we are handling
        // a request for the login servlet
        if (isAnonAllowed(request)) {

            try {
                ResourceResolver resolver = resourceResolverFactory.getResourceResolver(authInfo);

                // check whether the client asked for redirect after
                // authentication and/or impersonation
                if (DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response)) {

                    // request will now be terminated, so close the resolver
                    // to release resources
                    resolver.close();

                    return false;
                }

                // set the attributes for further processing
                setAttributes(resolver, null, request);

                return true;

            } catch (LoginException re) {

                // cannot login > fail login, do not try to authenticate
                handleLoginFailure(request, response, new AuthenticationInfo(null, "anonymous user"), re);
                return false;
            }
        }

        // If we get here, anonymous access is not allowed: redirect
        // to the login servlet
        log.debug("getAnonymousResolver: Anonymous access not allowed by configuration - requesting credentials");
        doLogin(request, response);

        // fallback to no session
        return false;
    }

    boolean isAnonAllowed(HttpServletRequest request) {

        String path = getPath(request);

        final Collection<AuthenticationRequirementHolder>[] holderSetArray =
                this.authenticationRequirementsManager.findApplicableHolders(request);
        for (int m = 0; m < holderSetArray.length; m++) {
            final Collection<AuthenticationRequirementHolder> holders = holderSetArray[m];
            if (holders != null) {
                for (AuthenticationRequirementHolder holder : holders) {
                    if (holder.isPathRequiresHandler(path)) {
                        return !holder.requiresAuthentication();
                    }
                }
            }
        }

        // fallback to anonymous not allowed (aka authentication required)
        return false;
    }

    /**
     * Returns credentials to use for anonymous resource access. If an anonymous
     * user is configued, this returns an {@link AuthenticationInfo} instance
     * whose authentication type is <code>null</code> and the user name and
     * password are set according to the {@link #PAR_ANONYMOUS_USER} and
     * {@link #PAR_ANONYMOUS_PASSWORD} configurations. Otherwise
     * the user name and password fields are just <code>null</code>.
     */
    private AuthenticationInfo getAnonymousCredentials() {
        AuthenticationInfo info = new AuthenticationInfo(null);
        if (this.anonUser != null) {
            info.setUser(this.anonUser);
            info.setPassword(this.anonPassword);
        }
        return info;
    }

    private boolean handleLoginFailure(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationInfo authInfo,
            final Exception reason) {

        String user = authInfo.getUser();
        boolean processRequest = false;
        if (reason.getClass().getName().contains("TooManySessionsException")) {

            // to many users, send a 503 Service Unavailable
            log.info("handleLoginFailure: Too many sessions for {}: {}", user, reason.getMessage());

            try {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "SlingAuthenticator: Too Many Users");
            } catch (IOException ioe) {
                log.error("handleLoginFailure: Cannot send status 503 to client", ioe);
            }

        } else if (reason instanceof LoginException) {
            log.info("handleLoginFailure: Unable to authenticate {}: {}", user, reason.getMessage());
            if (isAnonAllowed(request)
                    && !expectAuthenticationHandler(request)
                    && !AuthUtil.isValidateRequest(request)) {
                log.debug(
                        "handleLoginFailure: LoginException on an anonymous resource, fallback to getAnonymousResolver");
                processRequest = getAnonymousResolver(request, response, new AuthenticationInfo(null));
            } else {
                // request authentication information and send 403 (Forbidden)
                // if no handler can request authentication information.

                FAILURE_REASON_CODES code = FailureCodesMapper.getFailureReason(authInfo, reason);
                String message = null;
                switch (code) {
                    case ACCOUNT_LOCKED:
                        message = "Account is locked";
                        break;
                    case ACCOUNT_NOT_FOUND:
                        message = "Account was not found";
                        break;
                    case PASSWORD_EXPIRED:
                        message = "Password expired";
                        break;
                    case PASSWORD_EXPIRED_AND_NEW_PASSWORD_IN_HISTORY:
                        message = "Password expired and new password found in password history";
                        break;
                    case EXPIRED_TOKEN:
                        message = "Expired authentication token";
                        break;
                    case UNKNOWN:
                    case INVALID_LOGIN:
                    default:
                        message = "User name and password do not match";
                        break;
                }

                // preset a reason for the login failure
                request.setAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE, code);
                ensureAttribute(request, JakartaAuthenticationHandler.FAILURE_REASON, message);

                doLogin(request, response);
            }

        } else {

            if (log.isErrorEnabled()) {
                // general problem, send a 500 Internal Server Error
                log.error(String.format("handleLoginFailure: Unable to authenticate %s", user), reason);
            }

            try {
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "SlingAuthenticator: data access error, reason="
                                + reason.getClass().getSimpleName());
            } catch (IOException ioe) {
                log.error("handleLoginFailure: Cannot send status 500 to client", ioe);
            }
        }
        return processRequest;
    }

    /**
     * Tries to request credentials from the client. The following mechanisms
     * are implemented by this method:
     * <ul>
     * <li>If the request is a credentials validation request (see
     * {@link AuthUtil#isValidateRequest(HttpServletRequest)}
     * ) a 403/FORBIDDEN response is sent back.</li>
     * <li>If the request is not considered a
     * {@link #isBrowserRequest(HttpServletRequest) browser request} and the
     * HTTP Basic Authentication Handler is at least enabled for preemptive
     * credentials processing, a 401/UNAUTHORIZED response is sent back. This
     * helps implementing HTTP Basic authentication with WebDAV clients. If HTTP
     * Basic Authentication is completely switched of a 403/FORBIDDEN response
     * is sent back instead.</li>
     * <li>If the request is considered an
     * {@link #isAjaxRequest(HttpServletRequest) Ajax request} a 403/FORBIDDEN
     * response is simply sent back because we assume an Ajax requestor cannot
     * properly handle any request for credentials graciously.</li>
     * <li>Otherwise the {@link #login(HttpServletRequest, HttpServletResponse)}
     * method is called to try to find and call an authentication handler to
     * request credentials from the client. If none is available or willing to
     * request credentials, a 403/FORBIDDEN response is also sent back to the
     * client.</li>
     * </ul>
     * <p>
     * If a 403/FORBIDDEN response is sent back the {@link AuthUtil#X_REASON} header is
     * set to a either the value of the
     * {@link AuthenticationHandler#FAILURE_REASON} request attribute or to some
     * generic description describing the reason. To actually send the response
     * the
     * {@link AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)}
     * method is called.
     * <p>
     * This method is called in three situations:
     * <ul>
     * <li>If the request contains no credentials but anonymous login is not
     * allowed</li>
     * <li>If the request contains credentials but getting the Resource Resolver
     * using the provided credentials fails</li>
     * <li>If the selected authentication handler indicated any presented
     * credentials are not valid</li>
     * </ul>
     *
     * @param request The current request
     * @param response The response to send the credentials request (or access
     *            denial to)
     * @see AuthUtil#isValidateRequest(HttpServletRequest)
     * @see #isBrowserRequest(HttpServletRequest)
     * @see #isAjaxRequest(HttpServletRequest)
     * @see AuthUtil#sendInvalid(HttpServletRequest,
     *      HttpServletResponse)
     */
    private void doLogin(HttpServletRequest request, HttpServletResponse response) {

        if (!AuthUtil.isValidateRequest(request)) {

            if (AuthUtil.isBrowserRequest(request)) {

                if (!AuthUtil.isAjaxRequest(request) && !isLoginLoop(request)) {
                    try {

                        login(request, response);
                        return;

                    } catch (IllegalStateException ise) {

                        log.error("doLogin: Cannot login: Response already committed");
                        return;

                    } catch (NoAuthenticationHandlerException nahe) {

                        /*
                         * Don't set the failureReason for missing
                         * authentication handlers to not disclose this setup
                         * information.
                         */

                        log.error("doLogin: Cannot login: No AuthenticationHandler available to handle the request");
                    }
                }

            } else {

                // Presumably this is WebDAV. If HTTP Basic is fully enabled or
                // enabled for preemptive credential support, we just request
                // HTTP Basic credentials. Otherwise (HTTP Basic is fully
                // switched off, 403 is sent back)
                if (httpBasicHandler != null) {
                    httpBasicHandler.sendUnauthorized(response);
                    return;
                }
            }
        }

        // if we are here, we cannot redirect to the login form because it is
        // an XHR request or because there is no authentication handler willing
        // request credentials from the client or because it is a failed
        // credential validation

        // ensure a failure reason
        ensureAttribute(request, JakartaAuthenticationHandler.FAILURE_REASON, "Authentication Failed");

        AuthUtil.sendInvalid(request, response);
    }

    private boolean isExpiredToken(HttpServletRequest request) {
        return FAILURE_REASON_CODES.EXPIRED_TOKEN
                == request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE);
    }

    /**
     * Returns <code>true</code> if the current request was referred to by the
     * same URL as the current request has. This is assumed to be caused by a
     * loop in requesting credentials from the client. Such a loop will probably
     * never cause the request for credentials to succeed, so it must be broken.
     *
     * @param request The request to check
     * @return <code>true</code> if the request is considered to be a loop;
     *         <code>false</code> otherwise
     */
    private boolean isLoginLoop(final HttpServletRequest request) {

        if (isExpiredToken(request)) return false;

        String referer = request.getHeader("Referer");
        if (referer != null) {
            StringBuffer sb = request.getRequestURL();
            if (request.getQueryString() != null) {
                sb.append('?').append(request.getQueryString());
            }
            return referer.equals(sb.toString());
        }

        // no referer means no loop
        return false;
    }

    /**
     * Sets the name request attribute to the given value unless the request
     * attribute is already set a non-<code>null</code> value.
     *
     * @param request The request on which to set the attribute
     * @param attribute The name of the attribute to check/set
     * @param value The value to set the attribute to if it is not already set
     */
    private void ensureAttribute(final HttpServletRequest request, final String attribute, final Object value) {
        if (request.getAttribute(attribute) == null) {
            request.setAttribute(attribute, value);
        }
    }

    /**
     * Sets the request attributes required by the OSGi HttpContext interface
     * specification for the <code>handleSecurity</code> method. In addition the
     * {@link SlingAuthenticator#REQUEST_ATTRIBUTE_RESOLVER} request attribute
     * is set to the ResourceResolver.
     */
    private void setAttributes(
            final ResourceResolver resolver, final String authType, final HttpServletRequest request) {

        // HttpService API required attributes
        request.setAttribute(ServletContextHelper.AUTHENTICATION_TYPE, authType);
        if (authType != null) {
            request.setAttribute(ServletContextHelper.REMOTE_USER, resolver.getUserID());
        }

        // resource resolver for down-stream use
        request.setAttribute(REQUEST_ATTRIBUTE_RESOLVER, resolver);

        log.debug("setAttributes: ResourceResolver stored as request attribute: user={}", resolver.getUserID());
    }

    /**
     * Sends the session cookie for the name session with the given age in
     * seconds. This sends a Version 1 cookie.
     *
     * @param request The {@link HttpServletRequest}
     * @param response The {@link HttpServletResponse} on which to send
     *            back the cookie.
     * @param user The name of the user to impersonate as. This will be quoted
     *            and used as the cookie value.
     * @param maxAge The maximum age of the cookie in seconds. Positive values
     *            are persisted on the browser for the indicated number of
     *            seconds, setting the age to 0 (zero) causes the cookie to be
     *            deleted in the browser and using a negative value defines a
     *            temporary cookie to be deleted when the browser exits.
     * @param path The cookie path to use. This is intended to be the web
     *            application's context path. If this is empty or
     *            <code>null</code> the root path will be used assuming the web
     *            application is registered at the root context.
     * @param owner The name of the user originally authenticated in the request
     *            and who is now impersonating as <i>user</i>.
     */
    private void sendSudoCookie(
            HttpServletRequest request,
            HttpServletResponse response,
            final String user,
            final int maxAge,
            final String path,
            final String owner) {

        final String quotedUser;
        String quotedOwner = null;
        try {
            quotedUser = quoteCookieValue(user);
            if (owner != null) {
                quotedOwner = quoteCookieValue(owner);
            }
        } catch (IllegalArgumentException iae) {
            log.error(
                    "sendSudoCookie: Failed to quote value '{}' of cookie {}: {}",
                    user,
                    this.sudoCookieName,
                    iae.getMessage());
            return;
        } catch (UnsupportedEncodingException e) {
            log.error(
                    "sendSudoCookie: Failed to quote value '{}' of cookie {}: {}",
                    user,
                    this.sudoCookieName,
                    e.getMessage());
            return;
        }

        if (quotedUser != null) {
            final Cookie cookie = new Cookie(this.sudoCookieName, quotedUser);
            cookie.setHttpOnly(true);
            cookie.setSecure(request.isSecure());
            cookie.setMaxAge(maxAge);
            cookie.setPath((path == null || path.length() == 0) ? "/" : path);
            try {
                cookie.setComment(quotedOwner + " impersonates as " + quotedUser);
            } catch (IllegalArgumentException iae) {
                // ignore
            }

            response.addCookie(cookie);
        }
    }

    /**
     * Handles impersonation based on the request parameter for impersonation
     * (see {@link #sudoParameterName}) and the current setting in the sudo
     * cookie.
     * <p>
     * If the sudo parameter is empty or missing, the current cookie setting for
     * impersonation is used. Else if the parameter is <code>-</code>, the
     * current cookie impersonation is removed and no impersonation will take
     * place for this request. Else the parameter is assumed to contain the name
     * of a user to impersonate as.
     *
     * @param req The {@link HttpServletRequest} optionally containing
     *            the sudo parameter.
     * @param authInfo The authentication info into which the
     *            <code>sudo.user.id</code> property is set to the impersonator
     *            user.
     */
    private void handleImpersonation(HttpServletRequest req, AuthenticationInfo authInfo) {
        String currentSudo = getSudoCookieValue(req);

        /**
         * sudo parameter : empty or missing to continue to use the setting
         * already stored in the session; or "-" to remove impersonation
         * altogether (also from the session); or the handle of a user page to
         * impersonate as that user (if possible)
         */
        String sudo = req.getParameter(this.sudoParameterName);
        if (sudo == null || sudo.length() == 0) {
            sudo = currentSudo;
        } else if ("-".equals(sudo)) {
            sudo = null;
        }

        // sudo the session if needed
        if (sudo != null && sudo.length() > 0) {
            authInfo.put(ResourceResolverFactory.USER_IMPERSONATION, sudo);
        }
    }

    /**
     * Handles password change based on the request parameter for the new password
     * (see {@link #newPasswordParameterName}).
     * <p>
     * If the new password request parameter is present, it is added to the authInfo
     * object, which is later transformed to SimpleCredentials attributes.
     *
     * @param req The {@link HttpServletRequest} optionally containing
     *            the new password parameter.
     * @param authInfo The authentication info into which the
     *            <code>newPassword</code> property is set.
     */
    private void handlePasswordChange(HttpServletRequest req, AuthenticationInfo authInfo) {
        String newPassword = req.getParameter(PAR_NEW_PASSWORD);
        if (newPassword != null && newPassword.length() > 0) {
            authInfo.put("user.newpassword", newPassword);
        }
    }

    private String getSudoCookieValue(HttpServletRequest req) {
        // the current state of impersonation
        String currentSudo = null;
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (int i = 0; currentSudo == null && i < cookies.length; i++) {
                if (sudoCookieName.equals(cookies[i].getName())) {
                    currentSudo = unquoteCookieValue(cookies[i].getValue());
                }
            }
        }
        return currentSudo;
    }

    /**
     * Sets the impersonation cookie on the response if impersonation actually
     * changed and returns whether the cookie has been set (or cleared) or not.
     * <p>
     * The current impersonation state is taken from the sudo cookie value
     * while the desired state is taken from the user.impersonation
     * property of the auth info. If they don't match, the sudo cookie
     * is set according to the user.impersonation property where the
     * cookie is actually cleared if the property is <code>null</code>.
     *
     * @param req Providing the current sudo cookie value
     * @param res For setting the sudo cookie
     * @param authInfo Providing information about desired impersonation
     * @return <code>true</code> if the cookie has been set or cleared or
     *         <code>false</code> if the cookie is not modified.
     */
    boolean setSudoCookie(HttpServletRequest req, HttpServletResponse res, AuthenticationInfo authInfo) {
        final String sudo = (String) authInfo.get(ResourceResolverFactory.USER_IMPERSONATION);
        final String currentSudo = getSudoCookieValue(req);

        boolean changed = false;

        // set the (new) impersonation
        if (sudo == null && currentSudo != null) {
            // Parameter set to "-" to clear impersonation, which was
            // active due to cookie setting

            // clear impersonation
            this.sendSudoCookie(req, res, "", 0, req.getContextPath(), authInfo.getUser());
            changed = true;

        } else if (sudo != null && !sudo.equals(currentSudo)) {
            // Parameter set to a name. As the cookie is not set yet
            // or is set to another name, send the cookie with current sudo

            // (re-)set impersonation
            this.sendSudoCookie(req, res, sudo, -1, req.getContextPath(), sudo);
            changed = true;
        }

        return changed;
    }

    /**
     * Returns the path to be used to select the authentication handler to login
     * or logout with.
     * <p>
     * This method uses the {@link Authenticator#LOGIN_RESOURCE} request
     * attribute. If this attribute is not set (or is not a string), the request
     * path info is used. If this is not set either, or is the empty string, "/"
     * is returned.
     *
     * @param request The request providing the request attribute or path info.
     * @return The path as set by the request attribute or the path info or "/"
     *         if neither is set.
     */
    private String getHandlerSelectionPath(HttpServletRequest request) {
        final Object loginPathO = request.getAttribute(Authenticator.LOGIN_RESOURCE);
        String path;
        if (loginPathO instanceof String) {
            path = (String) loginPathO;
            final String ctxPath = request.getContextPath();
            if (ctxPath != null && path.startsWith(ctxPath)) {
                path = path.substring(ctxPath.length());
            }
            if (path == null || path.length() == 0) {
                path = "/";
            }

        } else {
            path = getPath(request);
        }

        return path;
    }

    /**
     * If the response has not been committed yet, redirect to target requested
     * by the <code>resource</code> request attribute or parameter. If neither
     * is set to a non-null string, the request is redirected to the context
     * root.
     * <p>
     * The response is not reset though, since the handler may have set states
     * such as an updated HTTP session or some Cookie
     *
     * @param request The request providing the redirect target
     * @param response The response to send the redirect to
     */
    private void redirectAfterLogout(final HttpServletRequest request, final HttpServletResponse response) {

        // nothing more to do if the response has already been committed
        if (response.isCommitted()) {
            log.debug("redirectAfterLogout: Response has already been committed, not redirecting");
            return;
        }

        // find the redirect target from the resource attribute or parameter
        // falling back to the request context path (or /) if not set or invalid
        String target = AuthUtil.getLoginResource(request, request.getContextPath());
        if (!AuthUtil.isRedirectValid(request, target)) {
            log.warn("redirectAfterLogout: Desired redirect target is invalid; redirecting to '/'");
            target = request.getContextPath() + "/";
        }

        // redirect to there
        try {
            response.sendRedirect(target); // NOSONAR The redirect is checked for validity using AuthUtil
        } catch (IOException e) {
            log.error("Failed to redirect to the page: " + target, e);
        }
    }

    @SuppressWarnings("deprecation")
    private void postLoginEvent(final HttpServletRequest request, final AuthenticationInfo authInfo) {
        final Map<String, Object> properties = new HashMap<>();
        properties.put(SlingConstants.PROPERTY_USERID, authInfo.getUser());
        properties.put(AuthenticationInfo.AUTH_TYPE, authInfo.getAuthType());

        // allow extensions to supply additional properties
        final List<JakartaLoginEventDecorator> localList = this.jakartaLoginEventDecorators;
        for (final JakartaLoginEventDecorator decorator : localList) {
            decorator.decorateLoginEvent(request, authInfo, properties);
        }
        final List<LoginEventDecorator> localListDep = this.loginEventDecorators;
        for (final LoginEventDecorator decorator : localListDep) {
            decorator.decorateLoginEvent(JakartaToJavaxRequestWrapper.toJavaxRequest(request), authInfo, properties);
        }

        EventAdmin localEA = this.eventAdmin;
        if (localEA != null) {
            localEA.postEvent(new Event(AuthConstants.TOPIC_LOGIN, properties));
        }
    }

    /**
     * Post an event to let subscribers know that a login failure has occurred.  For examples, subscribers
     * to the {@link AuthConstants#TOPIC_LOGIN_FAILED} event topic may be used to implement a failed login throttling solution.
     */
    @SuppressWarnings("deprecation")
    private void postLoginFailedEvent(
            final HttpServletRequest request, final AuthenticationInfo authInfo, Exception reason) {
        // The reason for the failure may be useful to downstream subscribers.
        FAILURE_REASON_CODES reasonCode = FailureCodesMapper.getFailureReason(authInfo, reason);
        // if reason code is unknowm, it is problem some non-login related failure, so don't send the event
        if (reasonCode != FAILURE_REASON_CODES.UNKNOWN) {
            final Map<String, Object> properties = new HashMap<>();
            if (authInfo.getUser() != null) {
                properties.put(SlingConstants.PROPERTY_USERID, authInfo.getUser());
            }
            if (authInfo.getAuthType() != null) {
                properties.put(AuthenticationInfo.AUTH_TYPE, authInfo.getAuthType());
            }
            properties.put("reason_code", reasonCode.name());

            // allow extensions to supply additional properties
            final List<JakartaLoginEventDecorator> localList = this.jakartaLoginEventDecorators;
            for (final JakartaLoginEventDecorator decorator : localList) {
                decorator.decorateLoginFailedEvent(request, authInfo, properties);
            }
            final List<LoginEventDecorator> localListDep = this.loginEventDecorators;
            for (final LoginEventDecorator decorator : localListDep) {
                decorator.decorateLoginFailedEvent(
                        JakartaToJavaxRequestWrapper.toJavaxRequest(request), authInfo, properties);
            }

            EventAdmin localEA = this.eventAdmin;
            if (localEA != null) {
                localEA.postEvent(new Event(AuthConstants.TOPIC_LOGIN_FAILED, properties));
            }
        }
    }

    /**
     * Ensures the cookie value is properly quoted for transmission to the
     * client.
     * <p>
     * The problem is, that the character set of cookie values is limited by
     * RFC 2109 defining that a cookie value must be token or quoted-string
     * according to RFC-2616:
     * <pre>
     * token = 1*<any CHAR except CTLs or separators>
     * separators = "(" | ")" | "<" | ">" | "@"
     *                | "," | ";" | ":" | "\" | <">
     *                | "/" | "[" | "]" | "?" | "="
     *                | "{" | "}" | SP | HT
     *
     * quoted-string = ( <"> *(qdtext | quoted-pair ) <"> )
     * qdtext = <any TEXT except <">>
     * quoted-pair = "\" CHAR
     *
     * @param value The cookie value to quote
     * @return The quoted cookie value
     * @throws UnsupportedEncodingException
     * @throws IllegalArgumentException If the cookie value is <code>null</code>
     *             or cannot be quoted, primarily because it contains a quote
     *             sign.
     */
    static String quoteCookieValue(final String value) throws UnsupportedEncodingException {
        // method is package private to enable unit testing

        if (value == null) {
            throw new IllegalArgumentException("Cookie value may not be null");
        }

        StringBuilder builder = new StringBuilder(value.length() * 2);
        builder.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') {
                builder.append("\\\"");
            } else if (c == '@') {
                builder.append(c);
            } else if (c == 127 || (c < 32 && c != '\t')) {
                throw new IllegalArgumentException("Cookie value may not contain CTL character");
            } else {
                builder.append(URLEncoder.encode(String.valueOf(c), "UTF-8"));
            }
        }
        builder.append('"');

        return builder.toString();
    }

    /**
     * Removes (optional) quotes from a cookie value to get the raw value of the
     * cookie.
     *
     * @param value The cookie value to unquote
     * @return The unquoted cookie value
     */
    static String unquoteCookieValue(String value) {
        // method is package private to enable unit testing

        // return value unmodified if null or empty
        if (value == null || value.length() == 0) {
            return value;
        }

        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }

        StringBuilder builder = new StringBuilder();
        String[] values = value.split("\\\\");
        for (String v : values) {
            try {
                builder.append(URLDecoder.decode(v, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                builder.append(v);
            }
        }
        return builder.toString();
    }
}

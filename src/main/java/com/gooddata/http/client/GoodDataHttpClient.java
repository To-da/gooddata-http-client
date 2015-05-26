/*
 * Copyright (C) 2007-2014, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AUTH;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static org.apache.commons.lang.Validate.notNull;

/**
 * <p>Http client with ability to handle GoodData authentication.</p>
 *
 * <h3>Usage</h3>
 *
 * <h4>Authentication using login</h4>
 * <pre>
 * // create HTTP client with your settings
 * HttpClient httpClient = HttpClientBuilder.create().build();
 *
 * // create login strategy, which wil obtain SST via login
 * SSTRetrievalStrategy sstStrategy = new LoginSSTRetrievalStrategy("user@domain.com", "my secret");
 *
 * // wrap your HTTP client into GoodData HTTP client
 * HttpClient client = new GoodDataHttpClient(httpClient, new HttpHost("server.com", 123), sstStrategy);
 *
 * // use GoodData HTTP client
 * HttpGet getProject = new HttpGet("/gdc/projects");
 * getProject.addHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
 * HttpResponse getProjectResponse = client.execute(httpHost, getProject);
 * </pre>
 *
 * <h4>Authentication using super-secure token (SST)</h4>
 *
 * <pre>
 * // create HTTP client
 * HttpClient httpClient = ...
 *
 * // create login strategy (you must somehow obtain SST)
 * SSTRetrievalStrategy sstStrategy = new SimpleSSTRetrievalStrategy("my super-secure token");
 *
 * // wrap your HTTP client into GoodData HTTP client
 * HttpClient client = new GoodDataHttpClient(httpClient, sstStrategy);
 *
 * // use GoodData HTTP client
 * HttpGet getProject = new HttpGet("/gdc/projects");
 * getProject.addHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
 * HttpResponse getProjectResponse = client.execute(httpHost, getProject);
 * </pre>
 */
public class GoodDataHttpClient implements HttpClient {

    private static final String TOKEN_URL = "/gdc/account/token";
    public static final String COOKIE_GDC_AUTH_TT = "cookie=GDCAuthTT";
    public static final String COOKIE_GDC_AUTH_SST = "cookie=GDCAuthSST";

    static final String SST_HEADER = "X-GDC-AuthSST";
    static final String TT_HEADER = "X-GDC-AuthTT";

    private enum GoodDataChallengeType {
        SST, TT, UNKNOWN
    }

    private final Log log = LogFactory.getLog(getClass());

    private final HttpClient httpClient;

    private final SSTRetrievalStrategy sstStrategy;

    /** Host performing authentication - eg. issuing TT tokens */
    private final HttpHost authHost;

    /** this lock is used to ensure that no threads will try to send requests while authentication is performed */
    private final ReadWriteLock rwLock = new ReentrantReadWriteLock();

    /** this lock guards that only one thread enters the authentication (obtaining TT/SST) section */
    private final Lock authLock = new ReentrantLock();

    /** current SST (or null if not yet obtained) */
    private String sst;

    /** TT to be set into the header (or null if not yet obtained) */
    private String tt;


    /**
     * Construct object.
     * @param httpClient Http client
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    @Deprecated
    public GoodDataHttpClient(final HttpClient httpClient, final SSTRetrievalStrategy sstStrategy) {
        notNull(httpClient);
        this.httpClient = httpClient;
        if (sstStrategy instanceof LoginSSTRetrievalStrategy) {
            this.sstStrategy = sstStrategy;
            this.authHost = ((LoginSSTRetrievalStrategy) sstStrategy).getHttpHost();
        } else {
            throw new IllegalArgumentException("This constructor is deprecated and works with LoginSSTRetrievalStrategy argument only!");
        }
    }

    /**
     * Construct object.
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    @Deprecated
    public GoodDataHttpClient(final SSTRetrievalStrategy sstStrategy) {
        this(HttpClientBuilder.create().build(), sstStrategy);
    }

    /**
     * Construct object.
     * @param httpClient Http client
     * @param authHost http host
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    public GoodDataHttpClient(final HttpClient httpClient, final HttpHost authHost, final SSTRetrievalStrategy sstStrategy) {
        notNull(httpClient);
        notNull(authHost, "HTTP host cannot be null");
        notNull(sstStrategy);
        this.httpClient = httpClient;
        this.authHost = authHost;
        this.sstStrategy = sstStrategy;
    }

    /**
     * Construct object.
     * @param authHost http host
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    public GoodDataHttpClient(final HttpHost authHost, final SSTRetrievalStrategy sstStrategy) {
        this(HttpClientBuilder.create().build(), authHost, sstStrategy);
    }

    private GoodDataChallengeType identifyGoodDataChallenge(final HttpResponse response) {
        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
            final Header[] headers = response.getHeaders(AUTH.WWW_AUTH);
            if (headers != null) {
                for (final Header header : headers) {
                    final String challenge = header.getValue();
                    if (challenge.contains(COOKIE_GDC_AUTH_SST)) {
                        // this is actually not used as in refreshTT() we rely on status code only
                        return GoodDataChallengeType.SST;
                    } else if (challenge.contains(COOKIE_GDC_AUTH_TT)) {
                        return GoodDataChallengeType.TT;
                    }
                }
            }
        }
        return GoodDataChallengeType.UNKNOWN;
    }

    private HttpResponse handleResponse(final HttpHost httpHost, final HttpRequest request, final HttpResponse originalResponse, final HttpContext context) throws IOException {
        final GoodDataChallengeType challenge = identifyGoodDataChallenge(originalResponse);
        if (challenge == GoodDataChallengeType.UNKNOWN) {
            return originalResponse;
        }
        EntityUtils.consume(originalResponse.getEntity());

        final boolean entered = authLock.tryLock();

        if (entered) {
            try {
                //only one thread requiring authentication will get here.
                final Lock writeLock = rwLock.writeLock();
                writeLock.lock();
                boolean doSST = true;
                try {
                    if (challenge == GoodDataChallengeType.TT && sst != null) {
                        if (refreshTt()) {
                            doSST = false;
                        }
                    }
                    if (doSST) {
                        sst = sstStrategy.obtainSst(httpClient, authHost);
                        if (!refreshTt()) {
                            throw new GoodDataAuthException("Unable to obtain TT after successfully obtained SST");
                        }
                    }
                } catch (GoodDataAuthException e) {
                    return new BasicHttpResponse(new BasicStatusLine(originalResponse.getProtocolVersion(),
                            HttpStatus.SC_UNAUTHORIZED, e.getMessage()));
                } finally {
                    writeLock.unlock();
                }
            } finally {
                authLock.unlock();
            }
        }
        return this.execute(httpHost, request, context);
    }

    /**
     * Refresh temporary token.
     * @return
     * <ul>
     *     <li><code>true</code> TT refresh successful</li>
     *     <li><code>false</code> TT refresh unsuccessful (SST expired)</li>
     * </ul>
     * @throws GoodDataAuthException error
     */
    private boolean refreshTt() throws IOException {
        log.debug("Obtaining TT");

        final HttpGet getTT = new HttpGet(TOKEN_URL);
        getTT.addHeader(SST_HEADER, sst);
        try {
            final HttpResponse response = httpClient.execute(authHost, getTT, (HttpContext) null);
            final int status = response.getStatusLine().getStatusCode();
            switch (status) {
                case HttpStatus.SC_OK:
                    tt = TokenUtils.extractTT(response);
                    return true;
                case HttpStatus.SC_UNAUTHORIZED:
                    // we probably may check if SST challenge is present to be sure the problem is the expired TT
                    return false;
                default:
                    throw new GoodDataAuthException("Unable to obtain TT, HTTP status: " + status);
            }
        } finally {
            getTT.releaseConnection();
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public HttpParams getParams() {
        return httpClient.getParams();
    }

    @SuppressWarnings("deprecation")
    @Override
    public ClientConnectionManager getConnectionManager() {
        return httpClient.getConnectionManager();
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request) throws IOException {
        return execute(target, request, (HttpContext) null);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler) throws IOException {
        return execute(target, request, responseHandler, null);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context) throws IOException {
        HttpResponse resp = execute(target, request, context);
        return responseHandler.handleResponse(resp);
    }

    @Override
    public HttpResponse execute(HttpUriRequest request) throws IOException {
        return execute(request, (HttpContext) null);
    }

    @Override
    public HttpResponse execute(HttpUriRequest request, HttpContext context) throws IOException {
        final URI uri = request.getURI();
        final HttpHost httpHost = new HttpHost(uri.getHost(), uri.getPort(),
                uri.getScheme());
        return execute(httpHost, request, context);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler) throws IOException {
        return execute(request, responseHandler, null);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context)
            throws IOException {
        final HttpResponse resp = execute(request, context);
        return responseHandler.handleResponse(resp);
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request, HttpContext context) throws IOException {
        final Lock readLock = rwLock.readLock();
        readLock.lock();

        if (tt != null) {
            // this adds TT header to EVERY request to ALL hosts made by this HTTP client
            // however the server performs additional checks to ensure client is not using forged TT
            request.addHeader(TT_HEADER, tt);
        }

        final HttpResponse resp;
        try {
            resp = this.httpClient.execute(target, request, context);
        } finally {
            readLock.unlock();
        }
        return handleResponse(target, request, resp, context);
    }
}

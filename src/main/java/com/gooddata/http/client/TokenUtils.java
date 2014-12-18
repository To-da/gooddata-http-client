/*
 * Copyright (C) 2007-2014, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contains handy methods .
 */
class TokenUtils {

    private static final String SST_ENTITY = "userLogin";
    private static final String TT_ENTITY = "userToken";

    private static final String ANY_NAMED_VALUES = "(?:\\s*\"\\w+\"\\s*\\:\\s*\"[\\w/]+\"\\s*,?\\s*)*";
    private static final String TOKEN = "\\s*\"token\"\\s*\\:\\s*\"(\\S+?)\"\\s*,?\\s*";

    private TokenUtils() { }

    static String extractTokenFromBody(final HttpResponse response, final String entityName) throws IOException {
        final String responseBody = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity());
        return extractTokenFromBody(responseBody, entityName);
    }

    static String extractTokenFromBody(final String responseBody, final String entityName) throws IOException {
        final Pattern pattern = Pattern.compile("\\s*\\{\\s*\"" + entityName + "\"\\s*\\:\\s*\\{" + ANY_NAMED_VALUES + TOKEN + ANY_NAMED_VALUES + "\\}\\s*\\}\\s*");
        final Matcher matcher = pattern.matcher(responseBody);
        if (!matcher.matches()) {
            throw new GoodDataAuthException("Unable to login. Malformed response body: " + responseBody);
        }
        return matcher.group(1);
    }

    static String extractSST(final HttpResponse response) throws IOException {
        return extractTokenFromBody(response, SST_ENTITY);
    }

    static String extractTT(final HttpResponse response) throws IOException {
        return extractTokenFromBody(response, TT_ENTITY);
    }
}

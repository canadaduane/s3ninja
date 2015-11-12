/*
 * Made with all the love in the world
 * by scireum in Remshalden, Germany
 *
 * Copyright by scireum GmbH
 * http://www.scireum.de - info@scireum.de
 */

package ninja;

import sirius.kernel.commons.Strings;
import sirius.kernel.di.std.Part;
import sirius.kernel.di.std.Register;
import sirius.web.http.WebContext;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.net.URLEncoder;
import java.net.URLDecoder;
import java.io.UnsupportedEncodingException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.hash.Hashing.sha256;
import static com.google.common.io.BaseEncoding.base16;

/**
 * Hash calculator for <a href="http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html">AWS
 * signature v4 calculation</a>
 */
@Register(classes = Aws4HashCalculator.class)
public class Aws4HashCalculator {
    protected static final Pattern AWS_AUTH4_PATTERN =
            Pattern.compile("AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/s3/aws4_request, SignedHeaders=([^,"
                            + "]+), Signature=(.+)");

    @Part
    private Storage storage;

    /**
     * Determines if the given request contains an AWS4 auth token.
     *
     * @param ctx the request to check
     * @return <tt>true</tt> if the request contains an AWS4 auth token, <tt>false</tt>  otherwise.
     */
    public boolean supports(final WebContext ctx) {
        final Matcher aws4Header = buildMatcher(ctx);
        return aws4Header.matches();
    }

    private Matcher initializedMatcher(final WebContext ctx) {
        Matcher matcher = buildMatcher(ctx);
        return matcher.matches() ? matcher : null;
    }

    private Matcher buildMatcher(final WebContext ctx) {
        return AWS_AUTH4_PATTERN.matcher(ctx.getHeaderValue("Authorization").asString(""));
    }

    /**
     * Computes the authentication hash as specified by the AWS SDK for verification purposes.
     *
     * @param ctx the current request to fetch parameters from
     * @return the computes hash value
     * @throws Exception in case of an unexpected error
     */
    public String computeHash(WebContext ctx, String pathPrefix) throws Exception {
        final MatchResult aws4Header = initializedMatcher(ctx);

        String date = aws4Header.group(2);
        String region = aws4Header.group(3);
        String key = "AWS4" + storage.getAwsSecretKey();

        byte[] dateKey = hmacSHA256(key.getBytes(UTF_8), date);
        byte[] dateRegionKey = hmacSHA256(dateKey, region);
        byte[] dateRegionServiceKey = hmacSHA256(dateRegionKey, "s3");
        byte[] signingKey = hmacSHA256(dateRegionServiceKey, "aws4_request");

        // System.out.println("String to Sign [AWS4]:" + buildStringToSign(ctx, pathPrefix));

        byte[] signedData = hmacSHA256(signingKey, buildStringToSign(ctx, pathPrefix));
        return base16().lowerCase().encode(signedData);
    }

    private String buildStringToSign(final WebContext ctx, String pathPrefix) {
        final StringBuilder canonicalRequest = buildCanonicalRequest(ctx, pathPrefix);
        final MatchResult aws4Header = initializedMatcher(ctx);

        String region = aws4Header.group(3);

        String credentialScope = getAmazonDateHeader(ctx).substring(0, 8) + "/"
                                 + region + "/"
                                 + "s3/aws4_request";
        
        // System.out.println("Canonical Request [AWS4]: " + canonicalRequest);

        return "AWS4-HMAC-SHA256\n"
               + getAmazonDateHeader(ctx) + "\n"
               + credentialScope + "\n"
               + hashedCanonicalRequest(canonicalRequest);
    }

    private String getAmazonDateHeader(final WebContext ctx) {
        return ctx.getHeaderValue("x-amz-date").asString();
    }

    private String canonicalQueryString(String queryString) {
        String queryStringWithoutQuestionMark;

        if (!queryString.isEmpty() && queryString.charAt(0) == '?') {
            queryStringWithoutQuestionMark = queryString.substring(1);
        } else {
            queryStringWithoutQuestionMark = queryString;
        }

        Map<String, String> params = this.createParameterMap(queryStringWithoutQuestionMark);
        SortedMap<String, String> sortedParamMap = new TreeMap<String, String>(params);
        return this.canonicalQueryString(sortedParamMap);
    }

    /**
     * Canonicalize the query string as required by Amazon.
     *
     * From bibsonomy-social (GPL licensed)
     * 
     * @param sortedParamMap    Parameter name-value pairs in lexicographical order.
     * @return                  Canonical form of query string.
     */
    private String canonicalQueryString(SortedMap<String, String> sortedParamMap) {
        if (sortedParamMap.isEmpty()) {
            return "";
        }

        StringBuffer buffer = new StringBuffer();
        Iterator<Map.Entry<String, String>> iter = sortedParamMap.entrySet().iterator();

        while (iter.hasNext()) {
            Map.Entry<String, String> kvpair = iter.next();
            buffer.append(percentEncodeRfc3986(kvpair.getKey()));
            buffer.append("=");
            buffer.append(percentEncodeRfc3986(kvpair.getValue()));
            if (iter.hasNext()) {
                buffer.append("&");
            }
        }
        String canonical = buffer.toString();
        return canonical;
    }

    /**
     * Percent-encode values according the RFC 3986. The built-in Java
     * URLEncoder does not encode according to the RFC, so we make the
     * extra replacements.
     *
     * From bibsonomy-social (GPL licensed)
     * 
     * @param s decoded string
     * @return  encoded string per RFC 3986
     */
    private String percentEncodeRfc3986(String s) {
        String out;
        try {
            /*
             * Somehow the encode() Method appends a carriage return and new line char to the string.
             * Therefore this signature does not match the Amazon signature.
             * 
             * This is not the most elegant way to fix, but replacing the "chars" is working for now.
             */
            out = URLEncoder.encode(s, "UTF-8")
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~")
                .replace("%0D%0A", "");
        } catch (UnsupportedEncodingException e) {
            out = s;
        }
        return out;
    }

    /**
     * Takes a query string, separates the constituent name-value pairs
     * and stores them in a hashmap.
     *
     * From bibsonomy-social (GPL licensed)
     * 
     * @param queryString
     * @return
     */
    private Map<String, String> createParameterMap(String queryString) {
        Map<String, String> map = new HashMap<String, String>();
        String[] pairs = queryString.split("&");

        for (String pair: pairs) {
            if (pair.length() < 1) {
                continue;
            }

            String[] tokens = pair.split("=",2);
            for(int j=0; j<tokens.length; j++)
            {
                try {
                    tokens[j] = URLDecoder.decode(tokens[j], "UTF-8");
                } catch (UnsupportedEncodingException e) {
                }
            }
            switch (tokens.length) {
                case 1: {
                    if (pair.charAt(0) == '=') {
                        map.put("", tokens[0]);
                    } else {
                        map.put(tokens[0], "");
                    }
                    break;
                }
                case 2: {
                    map.put(tokens[0], tokens[1]);
                    break;
                }
            }
        }
        return map;
    }

    private StringBuilder buildCanonicalRequest(final WebContext ctx, String pathPrefix) {
        final MatchResult aws4Header = initializedMatcher(ctx);

        // Remove '/s3' prefix and optionally add it back, depending on pathPrefix
        String requestedURI = pathPrefix + ctx.getRequestedURI().substring(3);

        StringBuilder canonicalRequest = new StringBuilder(ctx.getRequest().getMethod().name());
        canonicalRequest.append("\n");
        canonicalRequest.append(requestedURI);
        canonicalRequest.append("\n");
        canonicalRequest.append(canonicalQueryString(ctx.getQueryString()));
        canonicalRequest.append("\n");

        for (String name : aws4Header.group(4).split(";")) {
            canonicalRequest.append(name.trim());
            canonicalRequest.append(":");
            canonicalRequest.append(Strings.join(ctx.getRequest().headers().getAll(name), ",").trim());
            canonicalRequest.append("\n");
        }
        canonicalRequest.append("\n");
        canonicalRequest.append(aws4Header.group(4));
        canonicalRequest.append("\n");
        canonicalRequest.append(ctx.getHeader("x-amz-content-sha256"));
        return canonicalRequest;
    }

    private String hashedCanonicalRequest(final StringBuilder canonicalRequest) {
        return sha256().hashString(canonicalRequest, UTF_8).toString();
    }

    private byte[] hmacSHA256(byte[] key, String value) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(value.getBytes(UTF_8));
    }
}

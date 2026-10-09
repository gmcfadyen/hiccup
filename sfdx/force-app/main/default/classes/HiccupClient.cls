/**
 * Calls hiccup's MCP endpoint (POST /mcp) through the "Hiccup" Named
 * Credential. The credential supplies the endpoint and the
 * "Authorization: Bearer hk_..." header, so no secret lives in code.
 */
public with sharing class HiccupClient {
    public static final String NAMED_CREDENTIAL = 'callout:Hiccup';

    public class HiccupException extends Exception {}

    /** Result of analyze_capture: the parsed summary object from hiccup. */
    public class Diagnosis {
        public String captureId;
        public Map<String, Object> findingCounts;
        public List<Object> topFindings;
    }

    /**
     * Upload one file and return hiccup's diagnosis.
     * @param fileName display name, e.g. the ContentVersion title
     * @param body     raw file bytes
     */
    public static Diagnosis analyze(String fileName, Blob body) {
        Map<String, Object> args = new Map<String, Object>{
            'content_base64' => EncodingUtil.base64Encode(body),
            'filename' => fileName
        };
        Map<String, Object> rpc = new Map<String, Object>{
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'tools/call',
            'params' => new Map<String, Object>{ 'name' => 'analyze_capture', 'arguments' => args }
        };

        HttpRequest req = new HttpRequest();
        req.setEndpoint(NAMED_CREDENTIAL + '/mcp');
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/json');
        req.setTimeout(120000);
        req.setBody(JSON.serialize(rpc));

        HttpResponse res = new Http().send(req);
        if (res.getStatusCode() != 200) {
            throw new HiccupException('hiccup returned HTTP ' + res.getStatusCode() + ': ' + truncate(res.getBody(), 300));
        }
        Map<String, Object> out = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
        if (out.containsKey('error')) {
            Map<String, Object> err = (Map<String, Object>) out.get('error');
            throw new HiccupException('hiccup protocol error: ' + err.get('message'));
        }
        Map<String, Object> result = (Map<String, Object>) out.get('result');
        List<Object> content = (List<Object>) result.get('content');
        String text = (String) ((Map<String, Object>) content[0]).get('text');
        Map<String, Object> payload = (Map<String, Object>) JSON.deserializeUntyped(text);
        if (Boolean.TRUE == result.get('isError')) {
            throw new HiccupException('hiccup could not analyse the file: ' + payload.get('error'));
        }
        Diagnosis d = new Diagnosis();
        d.captureId = (String) payload.get('capture_id');
        d.findingCounts = (Map<String, Object>) payload.get('findingCounts');
        d.topFindings = (List<Object>) payload.get('topFindings');
        return d;
    }

    private static String truncate(String s, Integer n) {
        return s == null || s.length() <= n ? s : s.substring(0, n);
    }
}

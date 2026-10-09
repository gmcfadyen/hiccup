/**
 * Finds the newest capture/log file attached to a Case, sends it to hiccup
 * and posts the diagnosis back as a private CaseComment.
 *
 * Callable three ways: from an Agentforce agent or Flow (the invocable
 * method), from Apex (enqueue), or from the "Hiccup Analyse" Flow action.
 * The callout runs in a Queueable because analysis can take several
 * seconds and async Apex has the larger heap that big captures need.
 */
public with sharing class HiccupCaseAnalyzer {
    // Extensions hiccup understands; content is sniffed server-side, so this
    // only avoids uploading screenshots and PDFs.
    @TestVisible private static final Set<String> EXTENSIONS =
        new Set<String>{ 'pcap', 'pcapng', 'cap', 'log', 'txt' };
    // Async heap is 12 MB and base64 grows the file by a third plus the
    // JSON copy, so refuse anything bigger than this rather than fail late.
    @TestVisible private static final Integer MAX_BYTES = 3 * 1024 * 1024;
    private static final Integer COMMENT_LIMIT = 3900;

    public class Request {
        @InvocableVariable(label='Case Id' required=true)
        public Id caseId;
    }

    public class Response {
        @InvocableVariable(label='Status')
        public String status;
    }

    @InvocableMethod(
        label='Analyse Case capture with Hiccup'
        description='Sends the newest pcap or SBC log attached to the case to Hiccup, finds the fault and posts the diagnosis and suggested fixes as a private case comment.')
    public static List<Response> analyse(List<Request> requests) {
        List<Response> out = new List<Response>();
        for (Request r : requests) {
            Response resp = new Response();
            resp.status = enqueue(r.caseId);
            out.add(resp);
        }
        return out;
    }

    /** Queue analysis for one case; returns a short status line. */
    public static String enqueue(Id caseId) {
        ContentVersion cv = newestCapture(caseId);
        if (cv == null) {
            comment(caseId, 'Hiccup: no pcap/pcapng/log/txt file is attached to this case yet.');
            return 'No capture file attached';
        }
        if (cv.ContentSize > MAX_BYTES) {
            comment(caseId, 'Hiccup: ' + cv.Title + ' is ' + (cv.ContentSize / 1024) + ' KB, above the '
                + (MAX_BYTES / 1024) + ' KB limit for in-Salesforce analysis. Trim the capture to the failing call and re-attach it.');
            return 'File too large';
        }
        System.enqueueJob(new AnalyseJob(caseId, cv.Id));
        return 'Analysis queued for ' + cv.Title;
    }

    @TestVisible
    private static ContentVersion newestCapture(Id caseId) {
        List<ContentDocumentLink> links = [
            SELECT ContentDocumentId FROM ContentDocumentLink WHERE LinkedEntityId = :caseId
        ];
        Set<Id> docIds = new Set<Id>();
        for (ContentDocumentLink l : links) docIds.add(l.ContentDocumentId);
        if (docIds.isEmpty()) return null;
        for (ContentVersion cv : [
            SELECT Id, Title, FileExtension, ContentSize
            FROM ContentVersion
            WHERE ContentDocumentId IN :docIds AND IsLatest = true
            ORDER BY CreatedDate DESC
        ]) {
            if (cv.FileExtension != null && EXTENSIONS.contains(cv.FileExtension.toLowerCase())) return cv;
        }
        return null;
    }

    public class AnalyseJob implements Queueable, Database.AllowsCallouts {
        private Id caseId;
        private Id versionId;
        public AnalyseJob(Id caseId, Id versionId) {
            this.caseId = caseId;
            this.versionId = versionId;
        }
        public void execute(QueueableContext ctx) {
            ContentVersion cv = [SELECT Title, FileExtension, VersionData FROM ContentVersion WHERE Id = :versionId];
            String name = cv.Title + (cv.FileExtension != null ? '.' + cv.FileExtension : '');
            try {
                HiccupClient.Diagnosis d = HiccupClient.analyze(name, cv.VersionData);
                comment(caseId, format(name, d));
            } catch (Exception e) {
                comment(caseId, 'Hiccup could not analyse ' + name + ': ' + e.getMessage());
            }
        }
    }

    /** Plain-text case comment: counts, then each top finding with advice. */
    @TestVisible
    private static String format(String fileName, HiccupClient.Diagnosis d) {
        String s = 'Hiccup analysis of ' + fileName + ' (capture ' + d.captureId + ')\n';
        Map<String, Object> c = d.findingCounts == null ? new Map<String, Object>() : d.findingCounts;
        s += 'Findings: ' + n(c.get('crit')) + ' critical, ' + n(c.get('warn')) + ' warning, '
            + n(c.get('notice')) + ' notice, ' + n(c.get('info')) + ' info\n';
        if (d.topFindings == null || d.topFindings.isEmpty()) {
            return s + '\nNo faults found in this capture.';
        }
        Integer shown = 0;
        for (Object o : d.topFindings) {
            if (shown >= 5) break;
            Map<String, Object> f = (Map<String, Object>) o;
            s += '\n[' + String.valueOf(f.get('severity')).toUpperCase() + '] ' + f.get('title') + '\n';
            List<Object> advice = (List<Object>) f.get('advice');
            if (advice != null && !advice.isEmpty()) {
                Map<String, Object> a = (Map<String, Object>) advice[0];
                if (a.get('whatsWrong') != null) s += 'Problem: ' + a.get('whatsWrong') + '\n';
                List<Object> fixes = (List<Object>) a.get('fixes');
                if (fixes != null) for (Object fx : fixes) s += '  Fix: ' + fx + '\n';
            } else if (f.get('detail') != null) {
                s += String.valueOf(f.get('detail')) + '\n';
            }
            shown++;
        }
        return s;
    }

    private static String n(Object o) {
        return o == null ? '0' : String.valueOf(o);
    }

    @TestVisible
    private static void comment(Id caseId, String body) {
        String b = body.length() > COMMENT_LIMIT ? body.substring(0, COMMENT_LIMIT) + '…' : body;
        insert new CaseComment(ParentId = caseId, CommentBody = b, IsPublished = false);
    }
}

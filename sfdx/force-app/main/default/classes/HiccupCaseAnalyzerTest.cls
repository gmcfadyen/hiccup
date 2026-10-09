@IsTest
private class HiccupCaseAnalyzerTest {
    private class Mock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            System.assertEquals('callout:Hiccup/mcp', req.getEndpoint());
            Map<String, Object> summary = new Map<String, Object>{
                'capture_id' => 'abc123',
                'findingCounts' => new Map<String, Object>{ 'crit' => 1, 'warn' => 0, 'notice' => 0, 'info' => 2 },
                'topFindings' => new List<Object>{ new Map<String, Object>{
                    'severity' => 'crit', 'title' => 'INVITE retransmitted x6 with no response',
                    'advice' => new List<Object>{ new Map<String, Object>{
                        'whatsWrong' => 'Nothing at the far end processed the request.',
                        'fixes' => new List<Object>{ 'Open UDP 5060 in both directions.' } } } } }
            };
            Map<String, Object> body = new Map<String, Object>{
                'jsonrpc' => '2.0', 'id' => 1,
                'result' => new Map<String, Object>{
                    'isError' => false,
                    'content' => new List<Object>{ new Map<String, Object>{ 'type' => 'text', 'text' => JSON.serialize(summary) } } }
            };
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setBody(JSON.serialize(body));
            return res;
        }
    }

    private static Case makeCase(String ext, Integer size) {
        Case c = new Case(Subject = 'No audio on trunk');
        insert c;
        ContentVersion cv = new ContentVersion(
            Title = 'trace', PathOnClient = 'trace.' + ext, VersionData = Blob.valueOf('x'.repeat(size)));
        insert cv;
        Id docId = [SELECT ContentDocumentId FROM ContentVersion WHERE Id = :cv.Id].ContentDocumentId;
        insert new ContentDocumentLink(LinkedEntityId = c.Id, ContentDocumentId = docId, ShareType = 'V');
        return c;
    }

    @IsTest
    static void postsDiagnosisAsPrivateComment() {
        Case c = makeCase('pcap', 20);
        Test.setMock(HttpCalloutMock.class, new Mock());
        Test.startTest();
        HiccupCaseAnalyzer.Request r = new HiccupCaseAnalyzer.Request();
        r.caseId = c.Id;
        HiccupCaseAnalyzer.analyse(new List<HiccupCaseAnalyzer.Request>{ r });
        Test.stopTest();
        CaseComment cc = [SELECT CommentBody, IsPublished FROM CaseComment WHERE ParentId = :c.Id];
        System.assert(cc.CommentBody.contains('INVITE retransmitted'), cc.CommentBody);
        System.assert(cc.CommentBody.contains('Open UDP 5060'), cc.CommentBody);
        System.assertEquals(false, cc.IsPublished);
    }

    @IsTest
    static void commentsWhenNoCaptureAttached() {
        Case c = makeCase('png', 20);
        Test.startTest();
        String status = HiccupCaseAnalyzer.enqueue(c.Id);
        Test.stopTest();
        System.assertEquals('No capture file attached', status);
        System.assertEquals(1, [SELECT COUNT() FROM CaseComment WHERE ParentId = :c.Id]);
    }

    @IsTest
    static void refusesOversizeFile() {
        Case c = makeCase('pcap', HiccupCaseAnalyzer.MAX_BYTES + 1);
        Test.startTest();
        String status = HiccupCaseAnalyzer.enqueue(c.Id);
        Test.stopTest();
        System.assertEquals('File too large', status);
    }
}

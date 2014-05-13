package net.ripe.db.whois.update.rest;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Mockito.*;
/**
 * Created by michel on 5/9/14.
 */
@RunWith(MockitoJUnitRunner.class)
public class SubAllocationWindowRESTCallerTest {

    @Mock
    HttpConnexionUtils httpConnexionUtils;
    @InjectMocks
    SubAllocationWindowRESTCaller subject;

    @Test
    public void testNullAnswer() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn(null);
        Assert.assertNull(subject.getSAW4(""));
        Assert.assertNull(subject.getSAW6(""));
    }

    @Test
    public void testNoAnswer() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn("");
        Assert.assertNull(subject.getSAW4(""));
        Assert.assertNull(subject.getSAW6(""));
    }

    @Test
    public void testDummyAnswerFails() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn("not a valid response");
        Assert.assertNull(subject.getSAW4(""));
        Assert.assertNull(subject.getSAW6(""));
    }

    @Test
    public void testNoOrgHandle() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn("" +
                "<?xml version=\"1.0\"?>\n" +
                "<customer>\n" +
                "<org_handle/>\n" +
                "<saw>\n" +
                "<saw_v4>24</saw_v4>\n" +
                "<saw_v6>48</saw_v6>\n" +
                "</saw>\n" +
                "</customer>");
        Assert.assertNull(subject.getSAW4(""));
        Assert.assertNull(subject.getSAW6(""));
    }

    @Test
    public void testExistingOrgHandleButNoSAW() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn("" +
                "<?xml version=\"1.0\"?>\n" +
                "<customer>\n" +
                "<org_handle>ORG-SA56-AFRINIC</org_handle>\n" +
                "<saw>\n" +
                "<saw_v4>None</saw_v4>\n" +
                "<saw_v6>None</saw_v6>\n" +
                "</saw>\n" +
                "</customer>");
        Assert.assertNull(subject.getSAW4(""));
        Assert.assertNull(subject.getSAW6(""));
    }

    @Test
    public void testSAW() {
        when(httpConnexionUtils.executeGet(any(String.class))).thenReturn("" +
                "<?xml version=\"1.0\"?>\n" +
                "<customer>\n" +
                "<org_handle>ORG-SA56-AFRINIC</org_handle>\n" +
                "<saw>\n" +
                "<saw_v4>24</saw_v4>\n" +
                "<saw_v6>48</saw_v6>\n" +
                "</saw>\n" +
                "</customer>");
        Assert.assertEquals(Integer.valueOf(24), subject.getSAW4(""));
        Assert.assertEquals(Integer.valueOf(48), subject.getSAW6(""));
    }
}

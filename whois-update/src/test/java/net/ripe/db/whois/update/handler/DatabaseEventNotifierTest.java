package net.ripe.db.whois.update.handler;

import com.google.common.collect.Maps;
import net.ripe.db.whois.common.PropertyConverter;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.mail.MailGateway;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verify;

/**
 * Created by yogesh on 6/17/14.
 */
@RunWith(MockitoJUnitRunner.class)
public class DatabaseEventNotifierTest {

    @Mock
    private MailGateway mailGateway;

    @Mock
    private PropertyConverter propertyConverter;

    @Mock
    private PreparedUpdate update;

    @Mock
    private RpslObject referenceObject;

    @Mock
    private RpslObject updatedObject;

    @InjectMocks
    private DatabaseEventNotifier subject;

    @Test
    public void test_properties_1() throws IOException {

        String jsonProperty = "" +
                "{\n" +
                "\""+DatabaseEventNotifier.ON_CREATE_KEY+"\":\"^organisation:.*$\"\n" +
                "\""+DatabaseEventNotifier.ON_MODIFY_KEY+"\":\"^organisation:.*$\"\n" +
                "\""+DatabaseEventNotifier.ON_DELETE_KEY+"\":\"^aut-num:.*$\"\n" +
                "\""+DatabaseEventNotifier.ON_NOOP_KEY+"\":\"^aut-num:.*$\"\n" +
                "}";

        Map<String,String> ruleMap = Maps.newHashMap();
        ruleMap.put(DatabaseEventNotifier.ON_CREATE_KEY, "^organisation:.*$");
        ruleMap.put(DatabaseEventNotifier.ON_MODIFY_KEY, "^organisation:.*$");
        ruleMap.put(DatabaseEventNotifier.ON_DELETE_KEY, "^aut-num:.*$");
        ruleMap.put(DatabaseEventNotifier.ON_NOOP_KEY, "^aut-num:.*$");
        ruleMap.put("randomKey", "^aut-num:.*$");

        when(propertyConverter.jsonToPropertyMap(jsonProperty)).thenReturn(
                ruleMap
        );

        subject.setNotificationProperties(jsonProperty);

        verify(propertyConverter, times(2)).stringToPattern("^organisation:.*$");
        verify(propertyConverter, times(2)).stringToPattern("^aut-num:.*$");
    }

    @Test
    public void test_execute_1() throws IOException {
        sendmail_scenario(
                Action.CREATE,
                DatabaseEventNotifier.ON_CREATE_KEY,
                "^organisation:.*$",
                null,
                "organisation: XYZ\nremarks: new",
                "[organisation] XYZ",
                MessageFormat.format(
                        DatabaseEventNotifier.DEFAULT_EMAIL_BODY,
                        "[organisation] XYZ",
                        DatabaseEventNotifier.ON_CREATE_ACTION,
                        "organisation: XYZ\nremarks: new"
                )
        );
    }

    @Test
    public void test_execute_2() throws IOException {
        sendmail_scenario(
                Action.DELETE,
                DatabaseEventNotifier.ON_DELETE_KEY,
                "^organisation:.*$",
                null,
                "organisation: XYZ\nremarks: existing",
                "[organisation] XYZ",
                MessageFormat.format(
                        DatabaseEventNotifier.DEFAULT_EMAIL_BODY,
                        "[organisation] XYZ",
                        DatabaseEventNotifier.ON_DELETE_ACTION,
                        "organisation: XYZ\nremarks: existing"
                )
        );
    }

    @Test
    public void test_execute_3() throws IOException {
        sendmail_scenario(
                Action.NOOP,
                DatabaseEventNotifier.ON_NOOP_KEY,
                "^organisation:.*$",
                null,
                "organisation: XYZ\nremarks: existing",
                "[organisation] XYZ",
                MessageFormat.format(
                        DatabaseEventNotifier.DEFAULT_EMAIL_BODY,
                        "[organisation] XYZ",
                        DatabaseEventNotifier.ON_NOOP_ACTION,
                        "organisation: XYZ\nremarks: existing"
                )
        );
    }

    @Test
    public void test_execute_4() throws IOException {
        sendmail_scenario(
                Action.MODIFY,
                DatabaseEventNotifier.ON_MODIFY_KEY,
                "^organisation:.*$",
                "organisation: XYZ\nremarks: old",
                "organisation: XYZ\nremarks: updated",
                "[organisation] XYZ",
                MessageFormat.format(
                        DatabaseEventNotifier.DEFAULT_MODIFIED_EMAIL_BODY,
                        "[organisation] XYZ",
                        DatabaseEventNotifier.ON_MODIFY_ACTION,
                        "organisation: XYZ\nremarks: old",
                        "organisation: XYZ\nremarks: updated"
                )
        );
    }

    @Test
    public void test_execute_5() throws IOException {
        sendmail_scenario(
                Action.MODIFY,
                null,
                null,
                "organisation: XYZ\nremarks: old",
                "organisation: XYZ\nremarks: updated",
                "[organisation] XYZ",
                null
        );
    }

    private void sendmail_scenario(
            Action action,
            String jsonPropertyKey,
            String filterRegex,
            String originalObjectRpsl,
            String objectRpsl,
            String emailKey,
            String expectedEmail) throws IOException {

        when(update.getAction()).thenReturn(
                action
        );

        if (Action.MODIFY.equals(action)) {
            when(update.getReferenceObject()).thenReturn(
                    referenceObject
            );
            when(referenceObject.toString()).thenReturn(
                    originalObjectRpsl
            );
            when(referenceObject.getFormattedKey()).thenReturn(
                    emailKey
            );
        }

        when(update.getUpdatedObject()).thenReturn(
                updatedObject
        );
        when(updatedObject.toString()).thenReturn(
                objectRpsl
        );
        when(updatedObject.getFormattedKey()).thenReturn(
                emailKey
        );

        if (filterRegex != null) {
            String jsonProperty = "" +
                    "{\n" +
                    "\""+jsonPropertyKey+"\":\""+filterRegex+"\"\n" +
                    "}";

            Map<String, String> ruleMap = Maps.newHashMap();
            ruleMap.put(jsonPropertyKey, filterRegex);

            when(propertyConverter.jsonToPropertyMap(jsonProperty)).thenReturn(
                    ruleMap
            );

            when(propertyConverter.stringToPattern(filterRegex)).thenReturn(
                    Pattern.compile(filterRegex, Pattern.DOTALL | Pattern.CASE_INSENSITIVE)
            );

            subject.setNotificationProperties(jsonProperty);

            subject.execute(update);

            verify(propertyConverter, times(1)).jsonToPropertyMap(any(String.class));
            verify(mailGateway, times(1)).sendEmail(
                    DatabaseEventNotifier.DEFAULT_EMAIL_RECIPIENT,
                    DatabaseEventNotifier.DEFAULT_EMAIL_SUBJECT,
                    expectedEmail
            );
        } else {
            subject.execute(update);

            verify(propertyConverter, times(0)).jsonToPropertyMap(any(String.class));
            verify(mailGateway, times(0)).sendEmail(
                    anyString(),
                    anyString(),
                    anyString()
            );
        }
    }
}

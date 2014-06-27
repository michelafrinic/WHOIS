package net.ripe.db.whois.update.handler;

import com.google.common.base.Joiner;
import com.google.common.collect.Maps;
import net.ripe.db.whois.common.PropertyConverter;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.mail.MailGateway;
import net.ripe.db.whois.update.mail.NotificationMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.EOFException;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by yogesh on 6/11/14.
 */
@Component
public class DatabaseEventNotifier {

    private final Logger LOGGER = LoggerFactory.getLogger(DatabaseEventNotifier.class);
    protected static final String ON_CREATE_KEY   = "onCreate";
    protected static final String ON_MODIFY_KEY   = "onModify";
    protected static final String ON_DELETE_KEY   = "onDelete";
    protected static final String ON_NOOP_KEY     = "onNoop";
    protected static final String NOTIFY_KEY      = "notify";
    protected static final String SUBJECT_KEY     = "subject";

    protected static final String ON_CREATE_ACTION  = "onCreate";
    protected static final String ON_MODIFY_ACTION  = "onModify";
    protected static final String ON_DELETE_ACTION  = "onDelete";
    protected static final String ON_NOOP_ACTION    = "onNoop";

    protected static final String DEFAULT_EMAIL_RECIPIENT =
            "hostmaster@afrinic.net";
    protected static final String DEFAULT_EMAIL_SUBJECT =
            "[WHOIS] Update notification";
    protected static final String DEFAULT_EMAIL_BODY =
            "{0} has been {1}.\n\nObject:\n{2}";
    protected static final String DEFAULT_MODIFIED_EMAIL_BODY =
            "{0} has been {1}.\n\nOld object:\n{2}\n\nNew object:\n{3}";

    private String emailRecipient       = DEFAULT_EMAIL_RECIPIENT;
    private String emailSubject         = DEFAULT_EMAIL_SUBJECT;
    private String emailBody            = DEFAULT_EMAIL_BODY;
    private String emailBodyModified    = DEFAULT_MODIFIED_EMAIL_BODY;

    private Map<Action,String> actionMap = Maps.newHashMap();
    private Map<Action,Pattern> regexMap = Maps.newHashMap();

    private final MailGateway mailGateway;
    private final PropertyConverter propertyConverter;

    @Autowired
    public DatabaseEventNotifier(final MailGateway mailGateway, final PropertyConverter propertyConverter) {
        this.mailGateway = mailGateway;
        this.propertyConverter = propertyConverter;
        actionMap.put(Action.CREATE, ON_CREATE_ACTION);
        actionMap.put(Action.MODIFY, ON_MODIFY_ACTION);
        actionMap.put(Action.DELETE, ON_DELETE_ACTION);
        actionMap.put(Action.NOOP, ON_NOOP_ACTION);
    }

    public void execute(final PreparedUpdate update) {
        switch (update.getAction()) {
            case CREATE:
            case DELETE:
            case NOOP:
                notifyIfMatch(
                        update.getUpdatedObject().toString(),
                        getRegexMap().get(update.getAction()),
                        new NotificationMessage(
                                getEmailRecipient(),
                                getEmailSubject(),
                                MessageFormat.format(
                                        getEmailBody(),
                                        update.getUpdatedObject().getFormattedKey(),
                                        getActionMap().get(update.getAction()),
                                        update.getUpdatedObject().toString()))
                );
                break;
            case MODIFY:
                notifyIfMatch(
                        update.getUpdatedObject().toString(),
                        getRegexMap().get(update.getAction()),
                        new NotificationMessage(
                                getEmailRecipient(),
                                getEmailSubject(),
                                MessageFormat.format(
                                        getEmailBodyModified(),
                                        update.getUpdatedObject().getFormattedKey(),
                                        getActionMap().get(update.getAction()),
                                        update.getReferenceObject().toString(),
                                        update.getUpdatedObject().toString()))
                );
                break;
            default:
                break;
        }
    }

    @Value("${event.notification:}")
    public void setNotificationProperties(String jsonProperty) {
        Map<String,String> propertyMap = null;
        try {
            propertyMap = propertyConverter.jsonToPropertyMap(jsonProperty);
        } catch (EOFException e) {
            // Ignore
        } catch (IOException e) {
            String message = "Exception parsing ${event.notification} properties. Value should be a valid JSON.";
            LOGGER.error(message, e);
            throw new RuntimeException(message);
        }
        if (propertyMap != null) {
            LOGGER.info("Event notification properties: {}", propertyMap);
            if (propertyMap.containsKey(ON_CREATE_KEY)) {
                regexMap.put(Action.CREATE, propertyConverter.stringToPattern(propertyMap.get(ON_CREATE_KEY)));
            }
            if (propertyMap.containsKey(ON_MODIFY_KEY)) {
                regexMap.put(Action.MODIFY, propertyConverter.stringToPattern(propertyMap.get(ON_MODIFY_KEY)));
            }
            if (propertyMap.containsKey(ON_DELETE_KEY)) {
                regexMap.put(Action.DELETE, propertyConverter.stringToPattern(propertyMap.get(ON_DELETE_KEY)));
            }
            if (propertyMap.containsKey(ON_NOOP_KEY)) {
                regexMap.put(Action.NOOP, propertyConverter.stringToPattern(propertyMap.get(ON_NOOP_KEY)));
            }
            if (propertyMap.containsKey(NOTIFY_KEY)) {
                emailRecipient = propertyMap.get(NOTIFY_KEY);
            }
            if (propertyMap.containsKey(SUBJECT_KEY)) {
                emailSubject = propertyMap.get(SUBJECT_KEY);
            }
        }
    }

    private void notifyIfMatch(String input, Pattern pattern, NotificationMessage email) {
        if (match(pattern, input)) {
            mailGateway.sendEmail(email.getRecipient(), email.getSubject(), email.getBody());
        }
    }

    private boolean match(Pattern pattern, String input) {
        return pattern != null && pattern.matcher(input).matches();
    }

    /* */
    @Override
    public String toString() {

        Map m = Maps.newHashMap(regexMap);
        m.put("Email Recipient", emailRecipient);
        m.put("Email Subject", emailSubject);

        Joiner.MapJoiner mapJoiner = Joiner.on("\n").useForNull("<not set>").withKeyValueSeparator("\t= ");

        return mapJoiner.join(m);
    }
    /* */

    public Map<Action, String> getActionMap() {
        return actionMap;
    }

    public Map<Action, Pattern> getRegexMap() {
        return regexMap;
    }

    public String getEmailRecipient() {
        return emailRecipient;
    }

    public String getEmailSubject() {
        return emailSubject;
    }

    public String getEmailBody() {
        return emailBody;
    }

    public String getEmailBodyModified() {
        return emailBodyModified;
    }
}

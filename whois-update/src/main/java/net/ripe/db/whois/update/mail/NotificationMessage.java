package net.ripe.db.whois.update.mail;

/**
 * Created by yogesh on 6/11/14.
 */
public class NotificationMessage {

    private String recipient;
    private String subject;
    private String body;

    public NotificationMessage(String recipient, String subject, String body) {
        this.recipient = recipient;
        this.subject = subject;
        this.body = body;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getBody() {
        return body;
    }

    public String getSubject() {
        return subject;
    }
}

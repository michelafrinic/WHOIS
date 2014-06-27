package net.ripe.db.whois.update.handler;

import net.ripe.db.whois.common.jmx.JmxBase;
import net.ripe.db.whois.common.source.SourceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jmx.export.annotation.ManagedOperation;
import org.springframework.jmx.export.annotation.ManagedOperationParameter;
import org.springframework.jmx.export.annotation.ManagedOperationParameters;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;

/**
 * Created by yogesh on 6/23/14.
 */
@Component
@ManagedResource(objectName = JmxBase.OBJECT_NAME_BASE + "Notifier", description = "Whois database event notifier")
public class DatabaseEventNotifierJmx extends JmxBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseEventNotifierJmx.class);

    private final DatabaseEventNotifier notifier;

    @Autowired
    public DatabaseEventNotifierJmx(DatabaseEventNotifier notifier, SourceContext sourceContext) {
        super(LOGGER);
        this.notifier = notifier;
    }

    @ManagedOperation(description = "Get event notifier properties.")
    public String getNotificationProperties() {
        StringBuilder sb = new StringBuilder();
        sb.append("==================\n");
        sb.append("| Properties set |\n");
        sb.append("==================\n");
        sb.append(notifier.toString());
        sb.append("\n");
        return sb.toString();
    }

    @ManagedOperation(description = "Set event notifier properties.")
    @ManagedOperationParameters({
            @ManagedOperationParameter(name = "jsonProperty", description = "Event notifier properties to set, in JSON format.")
    })
    public String setNotificationProperties(String jsonProperty) {
        notifier.setNotificationProperties(jsonProperty);
        return getNotificationProperties();
    }
}

package net.ripe.db.whois.update.handler;

import net.ripe.db.whois.common.jmx.JmxBase;
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
public class DatabaseEventNotifierJmx {

    private final DatabaseEventNotifier notifier;

    @Autowired
    public DatabaseEventNotifierJmx(DatabaseEventNotifier notifier) {
        this.notifier = notifier;
    }

    @ManagedOperation(description = "Set event notifier properties.")
    @ManagedOperationParameters({
            @ManagedOperationParameter(name = "jsonProperty", description = "Event notifier properties to set, in JSON format.")
    })

    private String setNotificationProperties(String jsonProperty) {
        notifier.setNotificationProperties(jsonProperty);
        return "Properties successfully set.";
    }
}
